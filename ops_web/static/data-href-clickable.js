document.querySelectorAll('[data-href]').forEach(function (el) {
    el.addEventListener('click', function () {
        window.location = this.dataset.href;
    });
});
