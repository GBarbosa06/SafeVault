import tkinter as tk
from tkinter import messagebox
from cryptography.fernet import Fernet
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

import sqlite3
import secrets
import os

# ===== CRIPTO =====
cipher = None

def gerar_chave(senha_mestra):
    """
    Gera uma chave de criptografia a partir da senha mestra usando PBKDF2HMAC.
    É uma implementação mais segura que a antiga
        Não guarda a chave em um arquivo
            Gera dinamicamente a cada execução a partir da mestre
    """
    salt = b"safevault"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )

    key = base64.urlsafe_b64encode(
        kdf.derive(senha_mestra.encode())
    )

    return Fernet(key)

# ===== BANCO =====
conn = sqlite3.connect("safevault.db")
cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS credenciais (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site TEXT,
    usuario TEXT,
    senha TEXT
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY,
    verificacao BLOB
)
""")

conn.commit()

# ===== FUNÇÕES =====

def gerar_senha():
    senha = secrets.token_urlsafe(12)
    entry_senha.delete(0, tk.END)
    entry_senha.insert(0, senha)

def salvar():
    if cipher is None:
        messagebox.showerror("Erro", "Desbloqueie o cofre primeiro")
        return

    site = entry_site.get()
    usuario = entry_user.get()
    senha = entry_senha.get()

    senha_cripto = cipher.encrypt(senha.encode())

    cursor.execute(
        "INSERT INTO credenciais (site, usuario, senha) VALUES (?, ?, ?)",
        (site, usuario, senha_cripto)
    )
    conn.commit()

    messagebox.showinfo("Sucesso", "Senha salva!")

def listar():
    cursor.execute("SELECT id, site, usuario, senha FROM credenciais")
    dados = cursor.fetchall()

    texto = ""
    for id_, site, user, senha in dados:
        texto += f"[{id_}] {site} | {user} | {cipher.decrypt(senha).decode()}\n"

    messagebox.showinfo("Senhas", texto if texto else "Nenhuma senha")

def remover():
    id_remover = entry_id.get()

    if not id_remover:
        messagebox.showerror("Erro", "Digite um ID válido")
        return

    cursor.execute("DELETE FROM credenciais WHERE id = ?", (int(id_remover),))
    conn.commit()

    messagebox.showinfo("Sucesso", "Senha removida!")


def desbloquear():
    """
    Desbloqueia o cofre gerando a chave de criptografia a partir da senha mestra.
     - Se a senha mestra estiver vazia, exibe um erro.
     - Se a senha mestra for válida, gera a chave e exibe uma mensagem de sucesso.
     - A chave gerada é armazenada na variável global 'cipher'
    """
    global cipher

    senha_mestra = entry_master.get()

    if not senha_mestra:
        messagebox.showerror("Erro", "Digite a senha mestra")
        return

    cipher = gerar_chave(senha_mestra)

    cursor.execute("SELECT COUNT(*) FROM config")
    existe = cursor.fetchone()[0]

    if existe == 0:
        inicializar_verificacao()
        messagebox.showinfo("Sucesso", "Senha mestra criada!")
        return

    if validar_senha():
        messagebox.showinfo("Sucesso", "Cofre desbloqueado!")
    else:
        cipher = None
        messagebox.showerror("Erro", "Senha mestra incorreta")

def inicializar_verificacao():
    cursor.execute("SELECT verificacao FROM config WHERE id = 1")
    resultado = cursor.fetchone()

    if resultado is None:
        verificacao = cipher.encrypt(b"SAFEVAULT_OK")

        cursor.execute(
            "INSERT INTO config (id, verificacao) VALUES (1, ?)",
            (verificacao,)
        )

        conn.commit()

def validar_senha():
    cursor.execute("SELECT verificacao FROM config WHERE id = 1")
    resultado = cursor.fetchone()

    if resultado is None:
        return False

    try:
        cipher.decrypt(resultado[0])
        return True
    except:
        return False

# ===== INTERFACE =====

janela = tk.Tk()
janela.title("SafeVault")
tk.Label(janela, text="Senha mestra").pack()

entry_master = tk.Entry(janela, show="*") # Esconde a senha mestra
entry_master.pack()
tk.Label(janela, text="Site").pack()
entry_site = tk.Entry(janela)
entry_site.pack()

tk.Label(janela, text="Usuário").pack()
entry_user = tk.Entry(janela)
entry_user.pack()

tk.Label(janela, text="Senha").pack()
entry_senha = tk.Entry(janela)
entry_senha.pack()

tk.Label(janela, text="ID para remover").pack()
entry_id = tk.Entry(janela)
entry_id.pack()

tk.Button(janela, text="Desbloquear cofre", command=desbloquear).pack()
tk.Button(janela, text="Gerar senha", command=gerar_senha).pack()
tk.Button(janela, text="Salvar", command=salvar).pack()
tk.Button(janela, text="Listar senhas", command=listar).pack()
tk.Button(janela, text="Remover senha", command=remover).pack()

janela.mainloop()