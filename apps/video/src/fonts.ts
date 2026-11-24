// Font dimuat lewat @remotion/google-fonts agar render identik di semua mesin.
// Subset latin tidak memuat panah (U+2192) atau centang, jadi gunakan komponen Arrow/Check dari components/Glyphs.
import {loadFont as loadInter} from '@remotion/google-fonts/Inter';
import {loadFont as loadMono} from '@remotion/google-fonts/JetBrainsMono';
import {loadFont as loadCreepster} from '@remotion/google-fonts/Creepster';

export const sans = loadInter('normal', {weights: ['400', '500', '600', '700', '800'], subsets: ['latin']}).fontFamily;
export const mono = loadMono('normal', {weights: ['400', '600', '700'], subsets: ['latin']}).fontFamily;
// Hanya untuk "IT'S ALIVE" di S2
export const spooky = loadCreepster('normal', {weights: ['400'], subsets: ['latin']}).fontFamily;
