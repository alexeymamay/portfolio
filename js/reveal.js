/* Fade-in on scroll for sections without Webflow interactions */
(function(){
  if(!('IntersectionObserver' in window))return;
  if(window.matchMedia&&matchMedia('(prefers-reduced-motion: reduce)').matches)return;
  var sel='.archive-wrap,.collab,.header-center-box,.accordion-item,.di-attn,.di-role,.di-specs,.di-pol,.di-art,.di-rig,.di-geo,.uui-text-rich-text,.video-class,.uui-blogpost01_content figure,header figure.background-video';
  function run(){
    var els=[].slice.call(document.querySelectorAll(sel)).filter(function(e){return !e.closest('#Heading')&&!e.querySelector('.uui-text-rich-text')});
    var io=new IntersectionObserver(function(es){es.forEach(function(en){if(en.isIntersecting){en.target.classList.add('rv-in');io.unobserve(en.target)}})},{rootMargin:'0px 0px -8% 0px',threshold:0.08});
    els.forEach(function(e){e.classList.add('rv');io.observe(e)});
  }
  if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run);else run();
})();
