# Vila+Saúde — API

Servidor Python com API e SQLite para o protótipo acadêmico Vila+Saúde.

Executar localmente: `python server.py`. Variáveis: `HOST`, `PORT`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`, `COOKIE_SECURE`, `VILA_DB`.

**Atenção:** o servidor original ainda lê arquivos de interface em `static/`. Em hospedagem isolada, precisamos ajustar o tratamento das rotas estáticas e a comunicação entre UI e API (CORS/sessões) antes de usar produção. Evite expor dados reais, e nunca publique o banco nem senhas.
