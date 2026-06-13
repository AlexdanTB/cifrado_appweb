import { Routes } from '@angular/router';
import { HomeComponent } from './pages/home/home.component';
import { CifradoSimetricoComponent } from './pages/cifrado-simetrico/cifrado-simetrico.component';
import { CifradoAsimetricoComponent } from './pages/cifrado-asimetrico/cifrado-asimetrico.component';

export const routes: Routes = [
  { path: '', component: HomeComponent },
  { path: 'simetrico', component: CifradoSimetricoComponent },
  { path: 'asimetrico', component: CifradoAsimetricoComponent },
  { path: '**', redirectTo: '' }
];
