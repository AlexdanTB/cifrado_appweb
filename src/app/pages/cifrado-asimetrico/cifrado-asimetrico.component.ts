import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormsModule } from '@angular/forms';
import * as openpgp from 'openpgp';

@Component({
  selector: 'app-cifrado-asimetrico',
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: './cifrado-asimetrico.component.html',
  styleUrl: './cifrado-asimetrico.component.css'
})
export class CifradoAsimetricoComponent {

  name: string = '';
  email: string = '';
  passphrase: string = '';

  publicKey: string = '';
  privateKey: string = '';

  busy: boolean = false;

  async generate() {
    if (!this.passphrase.trim()) {
      alert('Ingrese una frase segura.');
      return;
    }

    this.busy = true;

    try {
      const userIDs = [{
        name: this.name || 'Usuario',
        email: this.email || 'usuario@example.com'
      }];

      const key = await openpgp.generateKey({
        type: 'rsa',
        rsaBits: 4096,
        userIDs,
        passphrase: this.passphrase
      });

      this.publicKey = key.publicKey;
      this.privateKey = key.privateKey;

      this.download('public.key', this.publicKey);
      this.download('private.key', this.privateKey);

    } catch (error) {
      console.error(error);
      alert('Error generando claves RSA.');
    } finally {
      this.busy = false;
    }
  }

  download(filename: string, content: string) {
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  copyToClipboard(text: string) {
    navigator.clipboard.writeText(text)
      .then(() => alert('Copiado al portapapeles'))
      .catch(() => alert('Error al copiar'));
  }

  clear() {
    this.name = '';
    this.email = '';
    this.passphrase = '';
    this.publicKey = '';
    this.privateKey = '';
  }
}
