// Recorrido en el navegador de la consola de la demo de Recon Scope (verificación temporal; es el paso 4 de la «Prueba de aceptación»
// de demo/README.md). Usa el Google Chrome que ya trae el servidor de GitHub. Termina con código 1 si algo no da lo esperado.
import { chromium } from 'playwright-core';
import { appendFileSync } from 'node:fs';

const BASE = 'http://127.0.0.1:4100';
const lines = [];
let failed = 0;
const check = (ok, text) => {
  const line = `${ok ? 'OK   ' : 'FALLA'} ${text}`;
  lines.push(line);
  console.log(line);
  if (!ok) failed += 1;
};
const escape = (text) => text.replaceAll('%', '%25').replaceAll('\r', '%0D').replaceAll('\n', '%0A');
const step = async (label, action) => {
  try {
    await action();
    check(true, label);
    return true;
  } catch (error) {
    check(false, `${label}: ${String(error.message).split('\n')[0]}`);
    return false;
  }
};

const browser = await chromium.launch({ channel: 'chrome' });
try {
  const problems = [];
  const watch = (page, label) => {
    page.on('console', (m) => { if (m.type() === 'error') problems.push(`${label} consola: ${m.text()}`); });
    page.on('pageerror', (e) => problems.push(`${label} excepción: ${e.message}`));
    page.on('requestfailed', (r) => problems.push(`${label} pedido fallido: ${r.url()}`));
  };

  // ---- Escritorio: los seis pasos de la demo ----
  const page = await (await browser.newContext({ viewport: { width: 1280, height: 900 } })).newPage();
  watch(page, 'escritorio');
  await page.goto(BASE, { waitUntil: 'domcontentloaded' });
  await page.locator('#status[data-state="ok"]').waitFor({ timeout: 90_000 });
  check((await page.locator('#status').innerText()).includes('Sistema listo'), 'arriba dice «Sistema listo»');

  let alive = await step('paso 1: se crea la cuenta de práctica (aceptando los términos de la demo)', async () => {
    await page.locator('#accept').check();
    await page.getByRole('button', { name: 'Crear cuenta' }).click();
    await page.getByText('Cuenta lista').waitFor({ timeout: 60_000 });
  });
  alive = alive && await step('paso 2: se registra tienda-demo.test y el motor entrega el código de verificación', async () => {
    await page.getByRole('button', { name: 'Registrar tienda-demo.test' }).click();
    await page.getByText('Dominio registrado').waitFor({ timeout: 60_000 });
  });
  alive = alive && await step('paso 3a: el motor se niega a escanear un dominio sin verificar', async () => {
    await page.getByRole('button', { name: 'Probar un escaneo ahora' }).click();
    await page.getByText('El motor rechazó el escaneo').waitFor({ timeout: 60_000 });
  });
  alive = alive && await step('paso 3b: sin el archivo publicado, la verificación de propiedad falla', async () => {
    await page.getByRole('button', { name: 'Verificar propiedad' }).click();
    await page.getByText('El motor no encontró el archivo con el código').waitFor({ timeout: 60_000 });
  });
  alive = alive && await step('paso 3c: con el archivo publicado, el motor lo pide por HTTPS y da la propiedad por demostrada', async () => {
    await page.getByRole('button', { name: 'Publicar el archivo en el sitio' }).click();
    await page.getByRole('button', { name: 'Retirar el archivo' }).waitFor({ timeout: 30_000 });
    await page.getByRole('button', { name: 'Verificar propiedad' }).click();
    await page.getByText('Propiedad demostrada').waitFor({ timeout: 90_000 });
  });
  alive = alive && await step('pasos 4 y 5: el primer escaneo termina con «2 altos, 1 medio, 5 bajos»', async () => {
    await page.getByRole('button', { name: 'Iniciar escaneo' }).click();
    await page.locator('.headline', { hasText: '2 altos, 1 medio, 5 bajos' }).waitFor({ timeout: 300_000 });
    const chips = (await page.locator('.result-head .chips .sev').allInnerTexts()).map((t) => t.trim());
    if (!['2 altos', '1 medio', '5 bajos'].every((c) => chips.includes(c))) throw new Error(`etiquetas de gravedad inesperadas: ${chips.join(', ')}`);
  });
  if (alive) {
    await page.screenshot({ path: 'escritorio-primer-escaneo.png', fullPage: true });
    await step('paso 6: al apagar el servidor de pruebas y escanear de nuevo queda «1 bajo»', async () => {
      await page.getByRole('button', { name: 'Apagar el servidor de pruebas' }).click();
      await page.getByRole('button', { name: 'Volver a encender el servidor de pruebas' }).waitFor({ timeout: 30_000 });
      await page.getByRole('button', { name: 'Escanear de nuevo' }).first().click();
      await page.locator('.headline').filter({ hasText: /^\s*1 bajo\s*$/ }).waitFor({ timeout: 300_000 });
    });
    await page.screenshot({ path: 'escritorio-segundo-escaneo.png', fullPage: true });
  }

  // ---- Celular ----
  const phone = await (await browser.newContext({ viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true })).newPage();
  watch(phone, 'celular');
  await phone.goto(BASE, { waitUntil: 'domcontentloaded' });
  await phone.locator('#status[data-state="ok"]').waitFor({ timeout: 90_000 });
  const overflow = await phone.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  check(overflow <= 1, `celular: sin desplazamiento horizontal (sobran ${overflow} px)`);
  await phone.screenshot({ path: 'celular.png', fullPage: true });

  check(problems.length === 0, `sin errores en la consola del navegador (${problems.length})${problems.length ? ': ' + problems.slice(0, 3).join(' | ') : ''}`);
} finally {
  await browser.close();
}

const ok = lines.length - failed;
const summary = `Recorrido en el navegador: ${ok} de ${lines.length} comprobaciones en orden`;
console.log(summary);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, `### Recorrido en el navegador\n\n\`\`\`\n${lines.join('\n')}\n\`\`\`\n\n`);
if (failed) {
  console.log(`::error title=Recorrido en el navegador::${escape([summary, '', ...lines.filter((l) => l.startsWith('FALLA'))].join('\n'))}`);
  process.exit(1);
}
console.log(`::notice title=Recorrido en el navegador::${escape([summary, '', ...lines].join('\n'))}`);
