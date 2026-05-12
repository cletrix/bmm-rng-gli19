# Pacote de Submissão BMM Testlabs Brasil — Lucky & Fun RNG Service

**Produto:** rng-service v1.0  
**Fabricante/Operador:** Lucky & Fun  
**Classificação:** Serviço Gerador de Números Aleatórios (RNG) para iGaming  
**Padrão de referência:** NIST SP 800-90A Rev.1, NIST SP 800-22 Rev.1a  

---

## Índice de Documentos

| Documento | Descrição |
|---|---|
| [01-design-document.md](01-design-document.md) | Documento de projeto — arquitetura e decisões de design |
| [02-algorithm-specification.md](02-algorithm-specification.md) | Especificação técnica do algoritmo AES-256-CTR DRBG |
| [03-entropy-sources.md](03-entropy-sources.md) | Fontes de entropia e política de re-seed |
| [04-statistical-testing.md](04-statistical-testing.md) | Metodologia de testes estatísticos e resultados |
| [05-security-controls.md](05-security-controls.md) | Controles de segurança e autenticação |
| [06-audit-trail.md](06-audit-trail.md) | Trilha de auditoria e rastreabilidade de outputs |
| [07-compliance-checklist.md](07-compliance-checklist.md) | Checklist de conformidade auto-avaliativa |
| [test-results/](test-results/) | Resultados dos testes estatísticos (gerado em runtime) |

## Como reproduzir os testes

```bash
# 1. Build com hash embutido
make build-release

# 2. Teste rápido NIST (1 milhão de bits)
./tests/nist/run_nist.sh

# 3. Suíte completa — 1 bilhão de bits (servidor Linux com STS + dieharder)
./tests/nist/run_billion.sh

# 4. Resultado dos testes de software (race detector)
go test -race ./...
```

## Contato Técnico

- **Empresa:** Lucky & Fun  
- **E-mail:** tech@luckyandfun.com.br  
- **Repositório:** privado (acesso sob NDA)
