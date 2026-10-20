# Tobi Hack — Projeto completo

Login do cliente, painel administrativo e sistema de licenças com verificação no servidor.

## Funcionalidades
- Geração de chaves de licença únicas.
- Durações de 1 semana (7 dias), 1 mês (30 dias) e 4 meses (120 dias).
- A validade começa no primeiro uso da chave pelo cliente, não na criação.
- Reentrar não reinicia o prazo.
- Licenças expiradas ou revogadas perdem acesso.
- Área administrativa protegida por senha definida no ambiente.
- Hash das chaves armazenado no banco, não a chave completa.
- Limitação básica de tentativas de login e cabeçalhos de segurança.
- Banco SQLite local; exige armazenamento persistente na hospedagem.

## Requisitos
- Node.js 20 ou superior.
- Um serviço de hospedagem que execute Node.js e mantenha o diretório `data/` persistente.

## Rodar localmente no Windows
1. Instale Node.js 20+.
2. Extraia este projeto para uma pasta.
3. Abra o terminal nessa pasta.
4. Execute `npm install`.
5. Copie `.env.example` para `.env`.
6. Edite `.env`: configure `ADMIN_PASSWORD` (mínimo 12 caracteres) e `COOKIE_SECRET` (mínimo 32 caracteres).
7. Para criar uma chave secreta, execute no terminal:
   `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"`
   Copie o resultado para `COOKIE_SECRET`.
8. Execute `npm start`.
9. Abra `http://localhost:3000` para o login ou `http://localhost:3000/admin` para administrar licenças.

## Fluxo de administração
1. Entre em `/admin` com a senha configurada em `ADMIN_PASSWORD`.
2. Escolha a duração e clique em **Gerar chave segura**.
3. Copie a chave: ela é exibida uma única vez.
4. Envie a chave ao cliente.
5. Quando o cliente utilizar a chave pela primeira vez, começa a contagem do prazo.
6. Na lista administrativa, você pode conferir o estado e revogar licenças.

## GitHub
1. Crie um repositório no GitHub.
2. Envie os arquivos do projeto, mas **não** envie `.env`, `node_modules/`, `data/` nem banco de dados.
3. `.gitignore` já exclui esses arquivos.
4. O GitHub armazena o código, mas não executa o servidor por conta própria.

## Publicação
Este projeto precisa de hospedagem para Node.js e de disco persistente para `data/licenses.db`. Configure no painel da hospedagem as variáveis `ADMIN_PASSWORD`, `COOKIE_SECRET`, `COOKIE_SECURE=true` e, se necessário, `PORT`. Use HTTPS. Se a plataforma não oferecer armazenamento persistente, o banco poderá ser perdido em reinicializações/deploys e será necessário usar banco de dados gerenciado.

## Sobre o painel
Os arquivos `painel.html`, `style.css` e `script.js` são os arquivos do painel anterior quando disponíveis. Se estiverem ausentes, substitua-os pelos arquivos finais do seu painel Tobi Hack. A proteção de `/painel` está no servidor; confirme também que o HTML não aponta para outros arquivos privados que estejam expostos por uma rota estática.

## Importante
- “1 mês” e “4 meses” significam 30 e 120 dias, não meses de calendário.
- A chave completa não pode ser recuperada depois de sair da resposta de criação; guarde-a antes de fechar.
- Faça backups do banco e teste o sistema antes de vender acesso.
