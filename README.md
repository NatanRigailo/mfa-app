# MFA Tokens

[![CI](https://github.com/NatanRigailo/mfa-app/actions/workflows/ci.yml/badge.svg)](https://github.com/NatanRigailo/mfa-app/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=NatanRigailo_mfa-app&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=NatanRigailo_mfa-app)
[![GHCR](https://img.shields.io/github/v/release/NatanRigailo/mfa-app?label=ghcr&logo=docker)](https://github.com/NatanRigailo/mfa-app/pkgs/container/mfa-app)

Aplicação web para armazenamento e consulta centralizada de tokens TOTP compartilhados entre equipes.

Funciona out-of-the-box com SQLite. MySQL é opcional.

**Demo:** [mfa.natan.tec.br](https://mfa.natan.tec.br)

---

## Demo

A instância de demonstração roda em [mfa.natan.tec.br](https://mfa.natan.tec.br) com dados fictícios pré-carregados (`DEMO_MODE=true`).

> **Atenção:** o demo usa o free tier do Render — dorme após 15 minutos sem acesso (cold start de ~30s) e o banco de dados reseta a cada redeploy. Não armazene tokens reais nessa instância.

Para ativar o modo demo na sua própria instância, defina `DEMO_MODE=true`. Na primeira inicialização com banco vazio, a aplicação carrega automaticamente um conjunto de tokens fictícios com nomes realistas e códigos TOTP funcionais.

---

## Quick start

```bash
docker run -d \
  -p 5000:5000 \
  -v mfa_data:/data \
  -e EDIT_PASS=suasenha \
  ghcr.io/natanrigailo/mfa-app:latest
```

Acesse `http://localhost:5000`.

---

## Docker Compose

```bash
# Clone e suba
docker compose up -d --build
```

Para usar MySQL, descomente o bloco `db` no `docker-compose.yml` e defina as variáveis `DB_*`.

---

## Variáveis de ambiente

| Variável        | Padrão        | Descrição                                                  |
|-----------------|---------------|------------------------------------------------------------|
| `APP_NAME`      | `MFA Tokens`  | Nome exibido na interface                                  |
| `SECRET_KEY`    | gerado        | Chave Flask para sessões — defina um valor fixo em produção|
| `EDIT_PASS`     | *(vazio)*     | Senha para ativar o modo de edição                         |
| `API_TOKEN`     | *(vazio)*     | Se definido, exige `Authorization: Bearer <token>` em `/get_new_codes` |
| `REGISTER_ABLE` | `true`        | Habilita o cadastro de novos tokens                        |
| `TABLE_NAME`    | `mfa_tokens`  | Nome da tabela no banco de dados                           |
| `MAX_UPLOAD_MB` | `5`           | Tamanho máximo do upload de QR code em MB                  |
| `DEMO_MODE`     | `false`       | Semeia tokens fictícios na primeira inicialização com banco vazio |
| `LOG_LEVEL`     | `INFO`        | Nível de log (`DEBUG`, `INFO`, `WARNING`, `ERROR`)         |
| `DB_HOST`       | —             | Host MySQL — se ausente, usa SQLite em `/data/tokens.db`   |
| `DB_USER`       | —             | Usuário MySQL                                              |
| `DB_PASSWORD`   | —             | Senha MySQL                                                |
| `DB_DATABASE`   | —             | Nome do banco MySQL                                        |

> **Atenção:** se `SECRET_KEY` não for definida, uma nova chave é gerada a cada reinício do container, invalidando todas as sessões ativas.

---

## Uso

### Consultar tokens

Acesse `/` — os tokens ativos são listados agrupados por letra, com código TOTP atualizado automaticamente e barra de progresso de 30s.

### Registrar token

Acesse `/register` com `REGISTER_ABLE=true`. Aceita chave Base32 digitada ou upload de imagem de QR code.

### Modo de edição

Clique no ícone de lápis (canto inferior direito) e informe o `EDIT_PASS`. No modo de edição é possível renomear tokens, ativar/desativar e remover.

---

## Desenvolvimento local

> **v2.0 (Go)** — em desenvolvimento na branch `beta`. As instruções abaixo são válidas para a v1.x (Python/Flask).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export EDIT_PASS=dev
export REGISTER_ABLE=true
export LOG_LEVEL=DEBUG

python app.py
```

A aplicação sobe em `http://0.0.0.0:5000` via Waitress.

---

## Roadmap

### v1.x — Concluído

**Pipeline CI/CD**
- [x] **Lint** — `flake8` *(v1.0.0)*
- [x] **SAST** — `bandit` *(v1.0.0)*
- [x] **Release** — auto-tag semver, build e push automático no GHCR *(v1.0.0)*
- [x] **Deploy automático** — webhook para o Render *(v1.1.0)*
- [x] **Release notes** — changelog automático com imagem Docker nas notas *(v1.1.0)*
- [x] **Dependabot** — atualização automática de dependências pip e GitHub Actions *(v1.1.3)*
- [x] **SonarCloud** — quality gate e security hotspots integrados ao CI *(v1.1.2)*
- [x] **Container scanning** — Trivy (CVEs na imagem) *(v1.1.14)*
- [x] **Badges** — CI, SonarCloud e GHCR no topo do README *(v1.1.4)*

**Funcionalidades**
- [x] Exclusão de tokens *(v1.0.0)*
- [x] **Demo mode** — seed de tokens fictícios na primeira inicialização com banco vazio *(v1.1.0)*
- [x] Migrações de schema com Alembic *(v1.1.1)*

---

### v2.0 — Em desenvolvimento

**Migração para Go**
- [ ] Rewrite da aplicação em Go — `net/http`, `go-otp`, `modernc/sqlite` ([#35](https://github.com/NatanRigailo/mfa-app/issues/35))
- [ ] Dockerfile multi-stage com imagem `scratch`/`distroless` (~15 MB vs ~200 MB atual) ([#36](https://github.com/NatanRigailo/mfa-app/issues/36))
- [ ] Pipeline adaptado para tooling Go — `golangci-lint`, `gosec`, `govulncheck` ([#37](https://github.com/NatanRigailo/mfa-app/issues/37))

**Pipeline CI/CD**
- [ ] Trigger unificado em `pull_request`, `permissions: contents: read` e Go module cache ([#26](https://github.com/NatanRigailo/mfa-app/issues/26))
- [ ] `hadolint` e `actionlint` no job de lint ([#27](https://github.com/NatanRigailo/mfa-app/issues/27))
- [ ] `gitleaks` para secret scanning ([#29](https://github.com/NatanRigailo/mfa-app/issues/29))
- [ ] Build refatorado com buildx e GHA layer cache ([#30](https://github.com/NatanRigailo/mfa-app/issues/30))
- [ ] Trivy estendido para `CRITICAL,HIGH` com `ignore-unfixed` ([#31](https://github.com/NatanRigailo/mfa-app/issues/31))
- [ ] SonarCloud — action atualizada e permissão de PR comments ([#32](https://github.com/NatanRigailo/mfa-app/issues/32))
- [ ] **DAST** — scan dinâmico com OWASP ZAP contra container efêmero ([#33](https://github.com/NatanRigailo/mfa-app/issues/33))
- [ ] Release workflow hardening e otimização ([#34](https://github.com/NatanRigailo/mfa-app/issues/34))

**Segurança**
- [ ] Rate limiting por IP no `toggle_edit` contra força bruta ([#38](https://github.com/NatanRigailo/mfa-app/issues/38))
- [x] Autenticação via `API_TOKEN` no `/get_new_codes` ([#39](https://github.com/NatanRigailo/mfa-app/issues/39))

**Qualidade**
- [ ] Suite de testes Go com `httptest` e banco in-memory ([#40](https://github.com/NatanRigailo/mfa-app/issues/40))
- [ ] `/healthz` com verificação real de conectividade ao banco ([#41](https://github.com/NatanRigailo/mfa-app/issues/41))

**Funcionalidades**
- [ ] Export/import de tokens como backup criptografado (AES-256-GCM) ([#42](https://github.com/NatanRigailo/mfa-app/issues/42))
