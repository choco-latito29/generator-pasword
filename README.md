# 🔑 pwgen — Generador de contraseñas en C

Un generador de contraseñas seguro, multiplataforma, escrito en **C**.  
Usa `/dev/urandom` (Linux/macOS) o CryptoAPI (Windows) como fuente de entropía.

---

## 🚀 Compilación

### Linux / macOS

```bash
gcc -O2 -Wall -o pwgen Src/pwgen.c
```
