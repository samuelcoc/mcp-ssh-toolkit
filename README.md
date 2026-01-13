# mcp-ssh-toolkit (Python)

Servidor **MCP** (Model Context Protocol) para executar comandos via **SSH** em servidores nomeados, definidos em um `servers.json`.

O foco aqui é ser prático e seguro:
- Configuração por **servidor** e por **grupo** (`groups`).
- **Hot reload** do `servers.json` (não precisa reiniciar o MCP a cada mudança).
- Suporte a **políticas** (`policy`) para **permitir/bloquear** comandos por regex.
- Suporte a senha **sem colocar senha no JSON** (via `passwordEnv`, `passwordCommand` ou `passwordKeyring`).

## Configuração via agente (LLM)

Depois que o MCP estiver ativo no seu host (opencode / Claude Desktop / etc), você pode pedir para o agente LLM configurar tudo pra você chamando as tools:
- `ssh_add_server` para adicionar/atualizar servidores
- `ssh_reload` (se quiser forçar recarregar, embora exista hot reload)
- `ssh_list` / `ssh_info` para validar o que ficou configurado

A recomendação é **passar segredos por env var** e só salvar no `servers.json` referências como `passwordEnv`.

## Arquivos

- `mcp_ssh_server.py`: servidor MCP via `stdio`.
- `servers.json`: sua configuração local (não commitar).
- `servers.example.json`: exemplo pronto (pode commitar).
- `USAGE.txt`: resumo rápido.

- `tests/test_mcp_ssh_server.py`: testes unitários básicos.

## Requisitos

- Python `>= 3.10`
- OpenSSH no `PATH` (para auth por chave/agent) **ou** `paramiko` (para auth por senha)

Opcional:
- `paramiko` (quando usar senha): `pip install paramiko`
- `keyring` (quando usar `passwordKeyring`): `pip install keyring`

## Como rodar

### 1) Rodar manualmente (stdio)

```bash
python mcp_ssh_server.py --config servers.json
```

Você também pode usar a env var:
- `MCP_SSH_CONFIG=...` (se não passar `--config`)

### 2) Usar no opencode

Edite o arquivo de config do opencode do seu usuário (ex.: `C:\Users\SEU_USUARIO\.config\opencode\opencode.json`) e adicione um MCP local.

Opção A (Anaconda):

```json
{
  "mcp": {
    "mcp-ssh": {
      "type": "local",
      "command": [
        "C:\\Users\\SEU_USUARIO\\anaconda3\\python.exe",
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\mcp_ssh_server.py",
        "--config",
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\servers.json"
      ],
      "enabled": true
    }
  }
}
```

Opção B (Python “normal” no PATH):

```json
{
  "mcp": {
    "mcp-ssh": {
      "type": "local",
      "command": [
        "python",
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\mcp_ssh_server.py",
        "--config",
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\servers.json"
      ],
      "enabled": true
    }
  }
}
```

No Windows, se você usa o launcher, também costuma funcionar com `py` (ex.: trocar `python` por `py`).

Reinicie o opencode depois de alterar o `opencode.json`.

### 3) Usar no Claude Desktop (Anthropic)

O Claude Desktop suporta MCP via config (procure por `claude_desktop_config.json`). Em Windows, normalmente fica em:
- `%APPDATA%\\Claude\\claude_desktop_config.json` (Windows)

Exemplo (Python no PATH):

```json
{
  "mcpServers": {
    "mcp-ssh": {
      "command": "python",
      "args": [
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\mcp_ssh_server.py",
        "--config",
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\servers.json"
      ]
    }
  }
}
```

Exemplo (Anaconda):

```json
{
  "mcpServers": {
    "mcp-ssh": {
      "command": "C:\\Users\\SEU_USUARIO\\anaconda3\\python.exe",
      "args": [
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\mcp_ssh_server.py",
        "--config",
        "C:\\Users\\SEU_USUARIO\\Desktop\\mcp-ssh-python\\servers.json"
      ]
    }
  }
}
```

Dica: se você precisa passar senhas via env vars (`passwordEnv`), configure as env vars no processo do Claude Desktop (ou inicie o Claude Desktop a partir de um terminal já com as env vars setadas, se aplicável).

## Configuração (`servers.json`)

Estrutura (v1):

```json
{
  "version": 1,

  "defaults": {
    "user": "ubuntu",
    "port": 22,
    "identityFile": "~/.ssh/id_ed25519",
    "strictHostKeyChecking": "accept-new|yes|no",
    "knownHostsFile": "~/.ssh/known_hosts",
    "extraArgs": ["-o", "BatchMode=yes"]
  },

  "policy": {
    "allow": ["^uptime$"],
    "deny": ["(?i)\\brm\\s+-rf\\b"]
  },

  "defaultServer": "nome-do-servidor",

  "groups": {
    "prod": ["prod-web", "prod-db"],
    "staging": ["staging"]
  },

  "servers": {
    "nome-do-servidor": {
      "host": "10.0.0.10",
      "port": 22,
      "user": "ubuntu",
      "identityFile": "~/.ssh/id_ed25519",

      "strictHostKeyChecking": "accept-new|yes|no",
      "knownHostsFile": "~/.ssh/known_hosts",
      "extraArgs": ["-o", "BatchMode=yes"],

      "passwordEnv": "SSH_PASSWORD_ENVVAR",
      "passwordCommand": ["op", "read", "op://vault/item/field"],
      "passwordKeyring": {"service": "mcp-ssh", "username": "ubuntu"},

      "policy": {
        "allow": ["^(uptime|whoami)$"],
        "deny": ["(?i)\\bshutdown\\b"]
      }
    }
  }
}
```

### Policy (allow/deny): modelo de decisão

A policy pode existir no root (`policy`) e também por servidor (`servers.<nome>.policy`). O modelo é:
- `deny` sempre bloqueia: se QUALQUER regex em `deny` bater, o comando é negado.
- `allow` é allowlist: se existir pelo menos um regex em `allow`, o comando só é permitido se bater em pelo menos um.
- Se `allow` estiver vazio/ausente, o padrão é "allow all" (exceto o que for negado por `deny`).
- Root + servidor são mesclados (acumulam): `allow_final = allow_global + allow_servidor`, `deny_final = deny_global + deny_servidor`.

### Segurança: comando remoto e shell

- `ssh_exec` envia `command` como uma string para o host remoto. Na prática, isso significa que **o comando é interpretado no lado remoto** (normalmente por um shell), então metacaracteres como `;`, `&&`, `|`, `>`, `<`, `$()`, crases, etc. podem alterar o que de fato executa.
- Isso é diferente de `passwordCommand`, que roda localmente **sem** `shell=True` (logo, não sofre interpretação de shell local).

Se você quiser um modo mais "hardening", a recomendação é:
- Preferir `policy.allow` com regex ancorada (ex.: `^(uptime|whoami)$`) para permitir só comandos simples.
- (Opcional) Bloquear metacaracteres via `policy.deny`.

Exemplo de `deny` para bloquear metacaracteres comuns (ajuste conforme sua necessidade):

```json
{
  "policy": {
    "deny": ["[;&|><`$()\\n\\r]"]
  }
}
```

### Autenticação (sem expor senha)


Recomendado:
- **Chave SSH** (`identityFile`) / ssh-agent (usa OpenSSH)

Para servidor com senha (usa `paramiko`):
- `passwordEnv`: pega a senha de uma env var
- `passwordCommand`: roda um comando e usa o stdout como senha (**sem `shell=True`**)
- `passwordKeyring`: lê do keyring do OS

Evite:
- `password` em texto plano no JSON

## Hot reload (não reiniciar sempre)

O MCP recarrega o `servers.json` automaticamente quando o arquivo muda (por `mtime`).

Além disso, existe:
- Tool `ssh_reload`: força recarregar imediatamente.

## Tools disponíveis

- `ssh_list`: lista servidores/grupos/defaults/policy
- `ssh_info`: mostra config sanitizada de um servidor (sem segredos)
- `ssh_test`: testa conexão/auth (server ou group)
- `ssh_exec`: executa em `server` ou `group` (sequencial)
- `ssh_exec_parallel`: executa em `group` (paralelo)
- `ssh_add_server`: adiciona/atualiza server e opcionalmente inclui em grupos
- `ssh_reload`: recarrega config do disco

## Exemplos de uso

### Executar em um servidor

```json
{"server":"kali-192.168.1.33","command":"cat /etc/os-release && uname -a","timeout_ms":30000}
```

### Executar em um grupo

```json
{"group":"lab","command":"uptime"}
```

### Executar em grupo (paralelo)

```json
{"group":"lab","command":"uname -a","max_parallel":8}
```

### Testar política deny/allow

- Se você configurar `policy.deny` com `(?i)\\brm\\s+-rf\\b` e tentar:

```json
{"server":"kali-192.168.1.33","command":"rm -rf /tmp/test"}
```

O MCP deve retornar erro `-32602` informando que o comando foi bloqueado pela policy.

## Tool `ssh_add_server` (adicionar sem reiniciar)

Exemplo: adiciona `srv1`, coloca no grupo `prod` e define como default:

```json
{
  "server": "srv1",
  "host": "10.0.0.10",
  "port": 22,
  "user": "ubuntu",
  "identityFile": "~/.ssh/id_ed25519",
  "groups": ["prod"],
  "setDefault": true
}
```

Observação:
- Por padrão, `ssh_add_server` **não aceita** `password` em texto plano.
- Se você quiser liberar isso no laboratório, rode com:
  - `MCP_SSH_ALLOW_PLAINTEXT_PASSWORD=1`

## Testes

```bash
python -m unittest discover -s tests -p "test*.py"
```

## Troubleshooting

- **"ssh executable not found"**: instale/ative OpenSSH no Windows.
- **Senha via env não funciona**: a env var precisa existir no processo que inicia o MCP/opencode.
- **Config mudou e não refletiu**: use `ssh_reload` (ou confira permissões/mtime do arquivo).
