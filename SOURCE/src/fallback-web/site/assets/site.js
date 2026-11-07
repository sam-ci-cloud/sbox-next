/* Progressive enhancement only: client-side filter of the curated list. */
(function(){var input=document.getElementById('filter');if(!input)return;var rows=[].slice.call(document.querySelectorAll('[data-file-row]'));var count=document.getElementById('filter-count');var empty=document.getElementById('filter-empty');
function apply(){var q=input.value.toLowerCase().trim(),shown=0;rows.forEach(function(r){var hit=!q||r.getAttribute('data-search').indexOf(q)>=0;r.hidden=!hit;if(hit)shown++});count.textContent=shown+' of '+rows.length+' files';empty.hidden=shown>0}
input.addEventListener('input',apply);input.hidden=false;apply();})();
