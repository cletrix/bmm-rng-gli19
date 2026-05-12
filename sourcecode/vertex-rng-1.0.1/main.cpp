/* Copyright (c) 2018 TDA DESENVOLVIMENTO DE SOFTWARE
 * All rights reserved
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of TDA DESENVOLVIMENTO DE SOFTWARE
 *
 * The intellectual and technical concepts contained
 * herein are proprietary to TDA DESENVOLVIMENTO DE SOFTWARE
 * and are protected by trade secret or copyright law.
 *
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from TDA DESENVOLVIMENTO DE SOFTWARE
 */


#include "cJSON.h"
#include "CivetServer.h"
#include <cstring>
#include <string>
#include <iostream>
#include <vector>
#include <iterator>
#include <fcntl.h>
#include <unistd.h>

#define PORT "8085"

#define RANDOM_URI "/random"
bool exitNow = false;

#define INVALID_RESULT -1
#define INVALID_PARAM -2

static const auto USAGE_STR = "(/random?min=xxx&max=xxx&rep=x&num=xxx)";
static int fd = -1;

static unsigned request = 0; /* demo data: request counter */

static int SendJSON(struct mg_connection *conn, cJSON *json_obj) {
    char *json_str = cJSON_PrintUnformatted(json_obj);
    size_t json_str_len = strlen(json_str);

    /* Send HTTP message header */
    mg_send_http_ok(conn, "application/json; charset=utf-8", static_cast<long long int>(json_str_len));

    /* Send HTTP message content */
    mg_write(conn, json_str, json_str_len);

    /* Free string allocated by cJSON_Print* */
    cJSON_free(json_str);

    return (int) json_str_len;
}

int32_t scale(uint32_t rng_result, uint32_t range) {
    if (range < 1)
        return INVALID_PARAM;

    auto max_result = (uint32_t) ((((uint64_t) 0x100000000l) / range) * range);

    if ((max_result != 0) && (max_result <= rng_result))
        return INVALID_RESULT;

    return rng_result % range;
}

int genRandomList(uint32_t min, uint32_t max, bool replenish_flag, int qttyNumber, struct mg_connection *conn) {
    uint32_t rng_value = 0, range;
    double *randList;

    // has to be double because of the result being passed to JSON which only supports double numbers
    randList = (double *) malloc(qttyNumber * sizeof(double));
    range = 1 + max - min;

    if ((range < qttyNumber) && (!replenish_flag)) {
        mg_send_http_error(conn, 400,
                           "Error in parameter list, numbers quantity greater than range, without reposition\n");
        return true;

    }

    if (max < min) {
        mg_send_http_error(conn, 400, "Error in parameter list, min > max");
        return true;
    }

    for (int j = 0; j < qttyNumber; j++) {
        read(fd, &rng_value, sizeof(rng_value)); //reading uint32 random from /dev/random
        int32_t result = scale(rng_value, range) + min;

        bool repNumber = false;
        if (!replenish_flag) {

            for (int k = 0; k < j; k++) {
                if (randList[k] == result) {
                    repNumber = true;
                    break;
                }
            }
        }

        if (repNumber) {
            j--;
            continue;
        }

        randList[j] = result;  //if repeated ignore t
    }


    cJSON *obj2 = cJSON_CreateDoubleArray(randList, qttyNumber);

/* insufficient memory? */
    if (!obj2) {
        mg_send_http_error(conn,
                           500, "Server error");
        return 500;
    }

    SendJSON(conn, obj2);
    cJSON_Delete(obj2);

    return 0;
}

class GenRandom : public CivetHandler {
private:
    bool
    handleAll(const char *method,
              CivetServer *server,
              struct mg_connection *conn) {
        std::string s, numberList;
        uint32_t randValue, min, max, quantity;
        double arrayValues2[4];
        uint32_t valueParameter;
        std::string::size_type sz;     // alias of size_t
        bool replenish_flag;

        if (!CivetServer::getParam(conn, "min", s)) {
            mg_send_http_error(conn, 400, USAGE_STR);
            return true;
        }
        min = static_cast<uint32_t>(std::stof(s, nullptr));
        s = "";

        if (!CivetServer::getParam(conn, "max", s)) {
            mg_send_http_error(conn, 400, USAGE_STR);
            return true;
        }
        max = static_cast<uint32_t>(std::stof(s, nullptr));
        s = "";

        if (!CivetServer::getParam(conn, "rep", s)) {
            mg_send_http_error(conn, 400, USAGE_STR);
            return true;
        }

        replenish_flag = std::stoi(s, nullptr) != 0;

        s = "";

        if (!CivetServer::getParam(conn, "num", s)) {
            mg_send_http_error(conn, 400, USAGE_STR);
            return true;
        }
        quantity = static_cast<uint32_t>(std::stof(s, nullptr));

        s = "";

        genRandomList(min, max, replenish_flag, quantity, conn);

        return true;

    }

public:
    bool handleGet(CivetServer *server, struct mg_connection *conn) override {
        return handleAll("GET", server, conn);
    }

    bool handlePost(CivetServer *server, struct mg_connection *conn) override {
        return handleAll("POST", server, conn);
    }
};


int main(int argc, char *argv[]) {
    const char *options[] = {
            "listening_ports", PORT, nullptr};

    std::vector<std::string> cpp_options;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        fprintf(stderr, "Cannot open random device");
        return 1;
    }

    cpp_options.reserve((sizeof(options) / sizeof(options[0]) - 1));
    for (int i = 0; i < (sizeof(options) / sizeof(options[0]) - 1); i++) {
        cpp_options.emplace_back(options[i]);
    }

    CivetServer server(cpp_options); // <-- C++ style start

    GenRandom h_js;
    server.addHandler(RANDOM_URI, h_js);

    printf("Running at http://localhost:%s%s\n", PORT, RANDOM_URI);

    while (!exitNow) {
        sleep(1);
    }

    return 0;
}
