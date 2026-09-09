#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import json
import struct
import random
import string
import shutil
import zipfile
import hashlib
import base64
import tempfile

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import colorama
from colorama import Fore, Style

colorama.init(autoreset=True)

MAGIC = 0x9BCFB9FC
HEADER_SIZE = 0x100
MASTER_KEY = b"s5s5ejuDru4uchuF2drUFuthaspAbepE"
SKIP_ENCRYPT = {"manifest.json", "contents.json", "content.zipe", "texts", "pack_icon.png", "signatures.json"}

KEYS_DB = "keys.db"
CONTENTKEYS_LST = "contentkeys.lst"
MAX_WORKERS = min(32, (os.cpu_count() or 4) * 2)

IGNORE_FILES = {"desktop.ini", "thumbs.db", ".ds_store", "folder.jpg"}

def read_keys_db():
    keys = {}
    if os.path.exists(KEYS_DB):
        with open(KEYS_DB, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if '=' in line:
                    u, k = line.split('=', 1)
                    keys[u.strip()] = k.strip().encode()
    return keys

def read_contentkeys_lst():
    keys = {}
    if os.path.exists(CONTENTKEYS_LST):
        with open(CONTENTKEYS_LST, 'r') as f:
            header = f.readline().strip()
            if header == "!!! Content Key Entries List !!!":
                for line in f:
                    line = line.strip()
                    if ':' in line:
                        u, k = line.split(':', 1)
                        keys[u.strip()] = k.strip().encode()
    return keys

def load_all_keys():
    keys = read_keys_db()
    for u, v in read_contentkeys_lst().items():
        if u not in keys:
            keys[u] = v
    return keys

def aes256_cfb8(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != 32:
        key = key.ljust(32, b'\0')[:32]
    if len(iv) != 16:
        iv = iv.ljust(16, b'\0')[:16]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CFB8(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def create_header(uuid_str: str) -> bytes:
    hdr = bytearray(HEADER_SIZE)
    struct.pack_into('<I', hdr, 0, 0)
    struct.pack_into('<I', hdr, 4, MAGIC)
    struct.pack_into('<Q', hdr, 8, 0)
    hdr[16] = len(uuid_str)
    uuid_bytes = uuid_str.encode('utf-8')
    hdr[17:17 + len(uuid_str)] = uuid_bytes
    return bytes(hdr)

def sign_manifest(pack_dir: str):
    manifest_path = os.path.join(pack_dir, "manifest.json")
    with open(manifest_path, 'rb') as f:
        manifest_bytes = f.read()
    sha256_hash = hashlib.sha256(manifest_bytes).digest()
    signature_entry = {
        "hash": base64.b64encode(sha256_hash).decode('utf-8'),
        "path": "manifest.json"
    }
    with open(os.path.join(pack_dir, 'signatures.json'), 'w', encoding='utf-8') as f:
        f.write(json.dumps([signature_entry], indent=2))

def _encrypt_one_file(args):
    full_path, rel, existing_key = args
    if existing_key is not None:
        return {"path": rel, "key": existing_key}

    file_key = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    key_bytes = file_key.encode('utf-8')
    iv = key_bytes[:16]

    with open(full_path, 'rb') as f_in:
        plain_data = f_in.read()
    encrypted_data = aes256_cfb8(key_bytes, iv, plain_data)
    with open(full_path, 'wb') as f_out:
        f_out.write(encrypted_data)
    return {"path": rel, "key": file_key}

def encrypt_pack(pack_dir: str, keys: dict):
    manifest_path = os.path.join(pack_dir, "manifest.json")
    if not os.path.exists(manifest_path):
        raise FileNotFoundError("manifest.json not found")

    with open(manifest_path, 'r', encoding='utf-8') as f:
        manifest = json.load(f)

    uuid_str = manifest["header"]["uuid"]

    product_type = "skin_packs"
    if 'metadata' in manifest and 'product_type' in manifest['metadata']:
        product_type = manifest['metadata']['product_type']
    elif 'modules' in manifest and manifest['modules']:
        t = manifest['modules'][0].get('type')
        type_map = {
            'resources': 'resource_packs',
            'skin_pack': 'skin_packs',
            'world_template': 'world_templates',
            'data': 'behaviour_packs',
            'persona_piece': 'persona'
        }
        product_type = type_map.get(t, product_type)

    content_key = keys.get(uuid_str, MASTER_KEY)
    if isinstance(content_key, str):
        content_key = content_key.encode('utf-8')

    existing_contents = {}
    contents_json_path = os.path.join(pack_dir, "contents.json")
    if os.path.exists(contents_json_path):
        try:
            with open(contents_json_path, 'rb') as f:
                f.read(HEADER_SIZE)
                encrypted_data = f.read()
            iv = content_key[:16]
            decrypted = aes256_cfb8(content_key, iv, encrypted_data).rstrip(b'\x00')
            existing_data = json.loads(decrypted.decode('utf-8'))
            for item in existing_data.get("content", []):
                if "key" in item:
                    existing_contents[item["path"]] = item["key"]
        except Exception:
            pass

    contents = []
    files_to_encrypt = []

    for root, dirs, files in os.walk(pack_dir):
        rel_root = os.path.relpath(root, pack_dir).replace(os.sep, '/')
        if rel_root == '.':
            rel_root = ''

        for d in dirs:
            rel = (rel_root + '/' + d) if rel_root else d
            contents.append({"path": rel + '/'})

        for f in files:
            full_path = os.path.join(root, f)
            rel = (rel_root + '/' + f) if rel_root else f

            if f in SKIP_ENCRYPT or any(part in SKIP_ENCRYPT for part in rel.split('/')):
                contents.append({"path": rel})
                continue

            existing_key = existing_contents.get(rel)
            if existing_key is not None:
                contents.append({"path": rel, "key": existing_key})
            else:
                files_to_encrypt.append((full_path, rel, None))

    if files_to_encrypt:
        print(f"{Fore.LIGHTBLUE_EX}Encrypting {len(files_to_encrypt)} files...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(_encrypt_one_file, args) for args in files_to_encrypt]
            for future in as_completed(futures):
                contents.append(future.result())

    contents_json = {"version": 1, "content": contents}
    json_str = json.dumps(contents_json, separators=(',', ':'))
    iv = content_key[:16]
    encrypted_json = aes256_cfb8(content_key, iv, json_str.encode('utf-8'))

    with open(contents_json_path, 'wb') as f:
        f.write(create_header(uuid_str) + encrypted_json)

    sig = os.path.join(pack_dir, "signatures.json")
    if os.path.exists(sig):
        os.remove(sig)
    sign_manifest(pack_dir)

    return uuid_str, product_type, content_key

def get_premium_cache_path():
    """
    Restituisce il percorso della cartella premium_cache di Minecraft Bedrock.
    Cerca prima nel roaming (installazione normale) e poi in LocalAppData (Microsoft Store).
    """
    roaming = os.getenv("APPDATA")
    local = os.getenv("LOCALAPPDATA")

    # Percorso principale (versione ufficiale)
    if roaming:
        path1 = os.path.join(roaming, "Minecraft Bedrock", "premium_cache")
        if os.path.exists(path1):
            return path1

    # Percorso alternativo (Microsoft Store / Xbox)
    if local:
        path2 = os.path.join(
            local,
            "Packages",
            "Microsoft.MinecraftUWP_8wekyb3d8bbwe",
            "LocalState",
            "premium_cache"
        )
        if os.path.exists(path2):
            return path2

    # Fallback (se non esiste ancora, restituisce il primo)
    return os.path.join(roaming, "Minecraft Bedrock", "premium_cache") if roaming else ""

def get_skin_packs_folder():
    return os.path.join(get_premium_cache_path(), "skin_packs")

def list_installed_skin_packs():
    skin_folder = get_skin_packs_folder()
    installed = []
    if not os.path.exists(skin_folder):
        return installed

    iru_path = os.path.join(skin_folder, ".Iru.json")
    known_uuids = set()

    if os.path.exists(iru_path):
        try:
            with open(iru_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                known_uuids.add(entry.get("id", ""))
        except Exception:
            pass

    for filename in os.listdir(skin_folder):
        if filename.startswith('.') or filename.lower() in ('.iru.json', 'desktop.ini'):
            continue

        filepath = os.path.join(skin_folder, filename)
        if not os.path.isfile(filepath):
            continue

        try:
            with zipfile.ZipFile(filepath, 'r') as zf:
                manifest_data = None
                name = "Unknown"
                uuid = filename

                for name_in_zip in zf.namelist():
                    if name_in_zip.endswith('manifest.json') or name_in_zip == 'manifest.json':
                        try:
                            with zf.open(name_in_zip) as mf:
                                raw = mf.read()
                                try:
                                    manifest_data = json.loads(raw.decode('utf-8'))
                                except:
                                    pass
                        except Exception:
                            pass
                        break

                if manifest_data and 'header' in manifest_data:
                    uuid = manifest_data['header'].get('uuid', filename)
                    name = manifest_data['header'].get('name', 'Unknown')

                if name.lower() in ("pack.name", "unknown", "pack.description"):
                    for lang_file in zf.namelist():
                        if lang_file.endswith('en_US.lang') or lang_file.endswith('en_us.lang'):
                            try:
                                with zf.open(lang_file) as lf:
                                    content = lf.read().decode('utf-8', errors='ignore')
                                    for line in content.splitlines():
                                        line = line.strip()
                                        if line.startswith('pack.name=') or line.startswith('skinpack.'):
                                            real_name = line.split('=', 1)[1].strip()
                                            if real_name:
                                                name = real_name
                                                break
                            except Exception:
                                pass
                            break

                installed.append({
                    'uuid': uuid,
                    'name': name,
                    'filename': filename,
                    'filepath': filepath
                })

        except (zipfile.BadZipFile, Exception):
            continue

    installed.sort(key=lambda x: (x['uuid'] not in known_uuids, x['name'].lower()))
    return installed

def replace_pack_content(pack_filepath: str, custom_folder: str):
    temp_dir = tempfile.mkdtemp(prefix="skinmaster_")

    try:
        with zipfile.ZipFile(pack_filepath, 'r') as zf:
            zf.extractall(temp_dir)

        for root, dirs, files in os.walk(temp_dir):
            for f in files:
                lower = f.lower()
                full = os.path.join(root, f)

                if (
                    lower.endswith('.png') or
                    lower == 'skins.json' or
                    ('geometry' in lower and lower.endswith('.json'))
                ):
                    try:
                        os.remove(full)
                    except Exception:
                        pass

        copied = 0

        for item in os.listdir(custom_folder):
            lower = item.lower()

            if lower in IGNORE_FILES or lower == "manifest.json":
                continue

            src = os.path.join(custom_folder, item)
            dst = os.path.join(temp_dir, item)

            if os.path.isfile(src):
                shutil.copy2(src, dst)
                copied += 1

            elif os.path.isdir(src):
                if os.path.exists(dst):
                    shutil.rmtree(dst)
                shutil.copytree(src, dst)
                copied += 1

        keys = load_all_keys()
        uuid_str, _, _ = encrypt_pack(temp_dir, keys)

        tmp_zip = pack_filepath + ".tmp"

        with zipfile.ZipFile(
            tmp_zip,
            'w',
            zipfile.ZIP_DEFLATED,
            compresslevel=1
        ) as zf:
            for root, _, files in os.walk(temp_dir):
                for f in files:
                    full = os.path.join(root, f)
                    arcname = os.path.relpath(full, temp_dir)
                    zf.write(full, arcname)

        os.replace(tmp_zip, pack_filepath)
        return True

    except Exception as e:
        return False

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def import_skinpack():
    custom_folder = _get_custom_folder_path()

    if not custom_folder:
        return

    installed_packs = list_installed_skin_packs()

    if not installed_packs:
        _show_message_and_wait(
            "No skin packs found in premium_cache\\skin_packs",
            Fore.YELLOW
        )
        return

    target_pack = _get_target_pack_to_replace(installed_packs)

    if not target_pack:
        return

    _replace_and_show_result(target_pack, custom_folder)

def _get_custom_folder_path():
    while True:
        _clear_screen()

        print(
            f"{Fore.WHITE}_Minecraft SkinPack Importer Tool_"
            f"{Style.RESET_ALL}"
        )

        path = input(
            f"{Fore.WHITE}Enter Skinpack Directory Path: "
            f"(or write 'b' to return)\n> {Style.RESET_ALL}"
        ).strip().strip('"')

        if path.lower() == 'b':
            return None

        if os.path.isdir(path):
            return path

def _get_target_pack_to_replace(installed_packs):
    while True:
        _clear_screen()

        print(f"{Fore.WHITE}Installed skin packs:{Style.RESET_ALL}")

        for i, pack in enumerate(installed_packs, 1):
            if pack['name'].lower() in (
                "pack.name",
                "unknown",
                "pack.description"
            ):
                print(
                    f"{Fore.WHITE}[{i}] {pack['name']} "
                    f"({pack['uuid']}){Style.RESET_ALL}"
                )
            else:
                print(
                    f"{Fore.WHITE}[{i}] {pack['name']}"
                    f"{Style.RESET_ALL}"
                )

        choice = input(
            f"{Fore.WHITE}> Select the number of the pack to replace "
            f"(or 'b' to return): {Style.RESET_ALL}"
        ).strip()

        if choice.lower() == 'b':
            return None

        try:
            idx = int(choice) - 1

            if 0 <= idx < len(installed_packs):
                return installed_packs[idx]

        except ValueError:
            pass

def _replace_and_show_result(target_pack, custom_folder):
    success = replace_pack_content(
        target_pack['filepath'],
        custom_folder
    )

    _clear_screen()

    if success:
        print(
            f"{Fore.GREEN}Pack imported successfully into Minecraft"
            f"{Style.RESET_ALL}"
        )
        print(
            f"{Fore.GREEN}Restart Minecraft."
            f"{Style.RESET_ALL}"
        )
    else:
        print(
            f"{Fore.RED}Failed to import the pack."
            f"{Style.RESET_ALL}"
        )

    print(
        f"{Fore.YELLOW}Enter to return to the main menu."
        f"{Style.RESET_ALL}"
    )

    input()

def _clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def _show_message_and_wait(message, color=Fore.WHITE):
    _clear_screen()
    print(f"{color}{message}{Style.RESET_ALL}")
    input("Press Enter to continue...")

def clear_screen():
    import os
    import platform

    if platform.system() == "Windows":
        os.system('cls')
    else:
        os.system('clear')

def remove_skinpack():
    while True:
        clear_screen()

        print(
            f"{Fore.WHITE}[1] Remove a specific SkinPack"
            f"{Style.RESET_ALL}"
        )
        print(
            f"{Fore.WHITE}[2] Remove all SkinPacks"
            f"{Style.RESET_ALL}"
        )
        print(
            f"{Fore.WHITE}[3] Back to main menu"
            f"{Style.RESET_ALL}"
        )

        choice = input(
            f"{Fore.WHITE}> {Style.RESET_ALL}"
        ).strip()

        if choice == '1':
            installed = list_installed_skin_packs()

            if not installed:
                print(
                    f"{Fore.YELLOW}No skin packs found."
                    f"{Style.RESET_ALL}"
                )
                input(
                    f"{Fore.WHITE}Press Enter to continue..."
                    f"{Style.RESET_ALL}"
                )
                continue

            clear_screen()

            print(
                f"\n{Fore.YELLOW}Installed:"
                f"{Style.RESET_ALL}"
            )

            for i, pack in enumerate(installed, 1):
                print(
                    f"{Fore.WHITE}[{i}] {pack['name']}"
                    f"{Style.RESET_ALL}"
                )

            while True:
                c = input(
                    f"{Fore.WHITE}> Select (or 'b'): "
                    f"{Style.RESET_ALL}"
                ).strip()

                if c.lower() == 'b':
                    break

                try:
                    idx = int(c) - 1

                    if 0 <= idx < len(installed):
                        os.remove(installed[idx]['filepath'])

                        print(
                            f"{Fore.GREEN}Removed."
                            f"{Style.RESET_ALL}"
                        )

                        input(
                            f"{Fore.WHITE}Press Enter to continue..."
                            f"{Style.RESET_ALL}"
                        )

                        break

                except ValueError:
                    pass

                print(
                    f"{Fore.RED}Invalid."
                    f"{Style.RESET_ALL}"
                )

        elif choice == '2':
            if input(
                f"{Fore.RED}Remove ALL? (y/n): "
                f"{Style.RESET_ALL}"
            ).lower() == 'y':

                folder = get_skin_packs_folder()

                for f in os.listdir(folder):
                    if not f.startswith('.'):
                        try:
                            os.remove(os.path.join(folder, f))
                        except:
                            pass

                print(
                    f"{Fore.GREEN}All removed."
                    f"{Style.RESET_ALL}"
                )

                input(
                    f"{Fore.WHITE}Press Enter to continue..."
                    f"{Style.RESET_ALL}"
                )

        elif choice == '3':
            return

        else:
            print(
                f"{Fore.RED}Invalid option."
                f"{Style.RESET_ALL}"
            )

            input(
                f"{Fore.WHITE}Press Enter to continue..."
                f"{Style.RESET_ALL}"
            )

def encrypt_skinpack():
    while True:
        os.system(
            "cls" if os.name == "nt" else "clear"
        )

        print(
            f"{Fore.WHITE}Minecraft SkinPack Encryptor Tool"
            f"{Style.RESET_ALL}"
        )

        path = input(
            f"{Fore.WHITE}Enter the Skinpack directory path "
            f"(or type 'b' to go back):\n> {Style.RESET_ALL}"
        ).strip().strip('"')

        if path.lower() == 'b':
            return

        if (
            os.path.isdir(path)
            and os.path.isfile(os.path.join(path, "manifest.json"))
        ):
            break

    out = input(
        f"{Fore.WHITE}Output dir "
        f"(empty = current): {Style.RESET_ALL}"
    ).strip() or os.getcwd()

    try:
        keys = load_all_keys()
        uuid_str, _, _ = encrypt_pack(path, keys)

        tmp = os.path.join(out, f"{uuid_str}.zip")

        with zipfile.ZipFile(
            tmp,
            'w',
            zipfile.ZIP_DEFLATED,
            compresslevel=1
        ) as zf:
            for root, _, files in os.walk(path):
                for f in files:
                    full = os.path.join(root, f)
                    zf.write(
                        full,
                        os.path.relpath(full, path)
                    )

        final = os.path.join(out, uuid_str)

        if os.path.exists(final):
            os.remove(final)

        shutil.move(tmp, final)

        print(
            f"{Fore.GREEN}Saved: {final}"
            f"{Style.RESET_ALL}"
        )

    except Exception as e:
        print(
            f"{Fore.RED}Failed: {e}"
            f"{Style.RESET_ALL}"
        )

    input("Press Enter...")

def show_info():
    print(
        f"{Fore.LIGHTBLUE_EX}Skin Master"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.WHITE}version 1.2"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.WHITE}Developed by: xGG9 & a6wwp RX"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.WHITE}the original app that inspired similar tools"
        f"{Style.RESET_ALL}"
    )

    print()

    print(
        f"{Fore.RED}Notes"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.WHITE}ty for using our program --a6wwp"
        f"{Style.RESET_ALL}"
    )

    input(
        f"\n{Fore.WHITE}Enter to return to the main menu."
        f"{Style.RESET_ALL}"
    )

def main_menu():
    while True:
        os.system(
            'cls' if os.name == 'nt' else 'clear'
        )

        print(
            f"{Fore.LIGHTBLUE_EX}Skin Master"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.WHITE}version: 1.2"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.WHITE}[1] Import SkinPack into Minecraft"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.WHITE}[2] Remove SkinPacks from Minecraft"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.WHITE}[3] Encrypt a SkinPack"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.WHITE}[4] Info"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.WHITE}[5] Exit"
            f"{Style.RESET_ALL}"
        )

        choice = input(
            f"{Fore.WHITE}> {Style.RESET_ALL}"
        ).strip()

        if choice == '1':
            os.system(
                'cls' if os.name == 'nt' else 'clear'
            )
            import_skinpack()

        elif choice == '2':
            os.system(
                'cls' if os.name == 'nt' else 'clear'
            )
            remove_skinpack()

        elif choice == '3':
            os.system(
                'cls' if os.name == 'nt' else 'clear'
            )
            encrypt_skinpack()

        elif choice == '4':
            os.system(
                'cls' if os.name == 'nt' else 'clear'
            )
            show_info()

        elif choice == '5':
            print(
                f"{Fore.LIGHTBLUE_EX}Goodbye!"
                f"{Style.RESET_ALL}"
            )
            sys.exit(0)

        else:
            print(
                f"{Fore.RED}Invalid option."
                f"{Style.RESET_ALL}"
            )
            input("Press Enter...")

if __name__ == "__main__":
    main_menu()
