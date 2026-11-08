// Confirmation prompt for high-impact actions (CSP forbids inline handlers).
document.addEventListener("submit", function (e) {
  var msg = e.target.getAttribute("data-confirm");
  if (msg && !window.confirm(msg)) e.preventDefault();
});
