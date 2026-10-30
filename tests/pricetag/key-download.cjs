'use strict';
const assert = require('node:assert/strict');
// Do not log, screenshot, attach or persist a downloaded credential in test output.
module.exports = async function downloadKey(page, selector) {
 const panel = page.locator(selector);
 const pending = page.waitForEvent('download');
 await panel.getByRole('button', {name:'Download .key', exact:true}).click();
 const download = await pending;
 assert.ok(download.suggestedFilename().endsWith('.key'));
 const stream = await download.createReadStream();
 const chunks=[]; for await (const chunk of stream) chunks.push(chunk);
 const key=Buffer.concat(chunks).toString('utf8').trim();
 assert.ok(key && !/\s/.test(key), 'download must contain only the credential');
 assert.equal((await page.locator('body').textContent()).includes(key), false, 'secret rendered in page');
 const id=await panel.getAttribute('data-key-id');
 assert.ok(id, 'missing non-secret key metadata');
 await download.delete();
 return {id,key};
};
