# MFA Tokens

Aplicação web para armazenamento e consulta centralizada de tokens TOTP compartilhados entre equipes.

Funciona out-of-the-box com SQLite. MySQL é opcional.

---

## Quick start

```bash
docker run -d \
  -p 5000:5000 \
  -v mfa_data:/data \
  -e EDIT_PASS=suasenha \
  ghcr.io/sua-org/mfa-tokens:latest
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
| `REGISTER_ABLE` | `true`        | Habilita o cadastro de novos tokens                        |
| `TABLE_NAME`    | `mfa_tokens`  | Nome da tabela no banco de dados                           |
| `MAX_UPLOAD_MB` | `5`           | Tamanho máximo do upload de QR code em MB                  |
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

### Pipeline CI/CD (GitHub Actions)

- [x] **Lint** — `flake8` / `ruff` no push e em PRs
- [x] **SAST** — análise estática com `bandit` (Python) e `semgrep`
- [ ] **Release** — build e push de imagem Docker com tag semântica (`v1.2.3`) gerada automaticamente via `release-please` ou similar — **pendente: definir registry always-free (GHCR, Docker Hub free tier, etc.) dado budget zero**
- [ ] **DAST** — scan dinâmico com OWASP ZAP contra container efêmero — **bloqueado pelo Release**

### Segurança

- [ ] Proteção de força bruta no `toggle_edit` (rate limiting por IP)
- [ ] Autenticação no endpoint `/get_new_codes` via `API_TOKEN` (atualmente expõe todos os secrets sem auth)
- [ ] Suporte a HTTPS nativo (via Caddy sidecar ou configuração de certificado)

### Funcionalidades

- [x] Exclusão de tokens
- [ ] Suporte a migrações de schema com Alembic (evitar perda silenciosa em atualizações)
- [ ] Export / import de tokens (backup criptografado)

### Qualidade

- [ ] Testes unitários e de integração (`pytest`)
- [ ] Health check verificando conectividade real com o banco
