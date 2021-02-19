// do all this when a show-column-checkbox is clicked
document.querySelectorAll('.show-column-checkbox').forEach(function (el) {
    el.addEventListener('change', function () {
        // get the column to show or hide
        const col = document.getElementById(this.dataset.columnId);
        if (this.checked) {
            col.classList.add('show');
        } else {
            col.classList.remove('show');
        }
    });
});
