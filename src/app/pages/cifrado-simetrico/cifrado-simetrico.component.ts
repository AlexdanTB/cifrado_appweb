import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';

@Component({
  selector: 'app-cifrado-simetrico',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './cifrado-simetrico.component.html',
  styleUrl: './cifrado-simetrico.component.css'
})
export class CifradoSimetricoComponent {

  encryptPass = '';
  decryptPass = '';
  encryptAutoDownload = true;

  fileToEncrypt?: File;
  fileToDecrypt?: File;

  encryptStatus = '';
  decryptStatus = '';

  private readonly MAGIC = new TextEncoder().encode('AESGCMv1');
  private readonly VERSION = 1;
  private readonly SALT_LEN = 16;
  private readonly IV_LEN = 12;
  private readonly PBKDF2_ITER = 200_000;
  private readonly KEY_LEN = 256;

  onFileEncryptSelected(event: Event) {
    const inp = event.target as HTMLInputElement;
    if (inp.files?.length) {
      this.fileToEncrypt = inp.files[0];
      this.encryptStatus = `Archivo seleccionado: ${this.fileToEncrypt.name}`;
    }
  }

  onFileDecryptSelected(event: Event) {
    const inp = event.target as HTMLInputElement;
    if (inp.files?.length) {
      this.fileToDecrypt = inp.files[0];
      this.decryptStatus = `Archivo seleccionado: ${this.fileToDecrypt.name}`;
    }
  }

  async encrypt() {
    if (!this.fileToEncrypt) {
      this.encryptStatus = 'Selecciona un archivo para cifrar.';
      return;
    }
    if (!this.encryptPass || this.encryptPass.length < 6) {
      this.encryptStatus = 'La contraseña debe tener mínimo 6 caracteres.';
      return;
    }

    try {
      this.encryptStatus = 'Leyendo archivo...';
      const data = await this.readFile(this.fileToEncrypt);

      const salt = window.crypto.getRandomValues(new Uint8Array(this.SALT_LEN));
      const iv = window.crypto.getRandomValues(new Uint8Array(this.IV_LEN));

      this.encryptStatus = 'Derivando clave...';
      const key = await this.deriveKey(this.encryptPass, salt);

      this.encryptStatus = 'Cifrando...';
      const cipherBuffer = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        key,
        data
      );

      const filenameBytes = new TextEncoder().encode(this.fileToEncrypt.name);
      const nameLen = filenameBytes.length;

      const headerSize =
        this.MAGIC.length + 1 + this.SALT_LEN + this.IV_LEN + 2 + nameLen;

      const cipherBytes = new Uint8Array(cipherBuffer);
      const output = new Uint8Array(headerSize + cipherBytes.byteLength);

      let offset = 0;

      output.set(this.MAGIC, offset);
      offset += this.MAGIC.length;

      output[offset++] = this.VERSION;

      output.set(salt, offset);
      offset += this.SALT_LEN;

      output.set(iv, offset);
      offset += this.IV_LEN;

      output[offset++] = (nameLen >> 8) & 0xff;
      output[offset++] = nameLen & 0xff;

      output.set(filenameBytes, offset);
      offset += nameLen;

      output.set(cipherBytes, offset);

      const blob = new Blob([output], { type: 'application/octet-stream' });
      const name = this.fileToEncrypt.name + '.enc';

      this.encryptStatus = 'Archivo cifrado correctamente.';
      this.download(blob, name);

    } catch (e) {
      console.error(e);
      this.encryptStatus = 'Error al cifrar el archivo.';
    }
  }

  async decrypt() {
    if (!this.fileToDecrypt) {
      this.decryptStatus = 'Selecciona un archivo cifrado.';
      return;
    }
    if (!this.decryptPass) {
      this.decryptStatus = 'Debes ingresar la contraseña.';
      return;
    }

    try {
      this.decryptStatus = 'Leyendo archivo...';
      const buffer = await this.readFile(this.fileToDecrypt);
      const data = new Uint8Array(buffer);

      let offset = 0;

      const magic = data.slice(0, this.MAGIC.length);
      if (!this.compareArrays(magic, this.MAGIC)) {
        this.decryptStatus = 'Archivo inválido o corrupto.';
        return;
      }
      offset += this.MAGIC.length;

      const version = data[offset++];
      if (version !== this.VERSION) {
        this.decryptStatus = 'Versión de archivo incompatible.';
        return;
      }

      const salt = new Uint8Array(this.SALT_LEN);
      salt.set(data.subarray(offset, offset + this.SALT_LEN));
      offset += this.SALT_LEN;

      const iv = new Uint8Array(this.IV_LEN);
      iv.set(data.subarray(offset, offset + this.IV_LEN));
      offset += this.IV_LEN;

      const nameLen = (data[offset] << 8) | data[offset + 1];
      offset += 2;

      const filenameBytes = data.slice(offset, offset + nameLen);
      const originalName = new TextDecoder().decode(filenameBytes);
      offset += nameLen;

      const cipherBytes = data.slice(offset);
      const cipherBuffer = cipherBytes.buffer.slice(cipherBytes.byteOffset, cipherBytes.byteOffset + cipherBytes.byteLength) as ArrayBuffer;

      this.decryptStatus = 'Derivando clave...';
      const key = await this.deriveKey(this.decryptPass, salt);

      this.decryptStatus = 'Descifrando...';
      const plainBuffer = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        key,
        cipherBuffer
      );

      const blob = new Blob([plainBuffer], { type: 'application/octet-stream' });
      this.download(blob, originalName);

      this.decryptStatus = 'Archivo descifrado correctamente.';

    } catch (e) {
      console.error(e);
      this.decryptStatus = 'Error al descifrar. Contraseña incorrecta o archivo dañado.';
    }
  }

  private readFile(file: File): Promise<ArrayBuffer> {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onload = () => resolve(fr.result as ArrayBuffer);
      fr.onerror = () => reject(fr.error);
      fr.readAsArrayBuffer(file);
    });
  }

  private download(blob: Blob, filename: string) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  private async deriveKey(pass: string, salt: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
    const pwUtf8 = new TextEncoder().encode(pass);

    const baseKey = await window.crypto.subtle.importKey(
      'raw',
      pwUtf8,
      'PBKDF2',
      false,
      ['deriveKey']
    );

    return window.crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: this.PBKDF2_ITER,
        hash: 'SHA-256'
      },
      baseKey,
      { name: 'AES-GCM', length: this.KEY_LEN },
      false,
      ['encrypt', 'decrypt']
    );
  }

  private compareArrays(a: Uint8Array, b: Uint8Array) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) return false;
    }
    return true;
  }
}
