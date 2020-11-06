const md = new remarkable.Remarkable();

function render_markdown(e) {
    const target = document.getElementById(e.target.dataset.previewTarget);
    target.innerHTML = md.render(e.target.value);
}

document.querySelectorAll('textarea').forEach(function (el) {
    el.addEventListener('input', $.debounce(250, render_markdown));
});
