const filter_input = document.getElementById('filter-input');
const url_params = new URLSearchParams(window.location.search);

function do_filter (event) {
    if (event && event.keyCode === 27) {
        // [Esc] was pressed
        this.value = '';
    }
    let query = filter_input.value.toLowerCase();
    let items = document.querySelectorAll('.filter-candidate');
    if (query === '') {
        items.forEach(function (el) {
            el.classList.add('show');
        })
        url_params.delete('filter');
    } else {
        items.forEach(function (el) {
            if (el.dataset.filterValue.includes(query)) {
                el.classList.add('show');
            } else {
                el.classList.remove('show');
            }
        });
        url_params.set('filter', query);
    }
    window.history.pushState({}, '', `${location.pathname}?${url_params}`);
}

if (url_params.has('filter')) {
    do_filter();
}

// after removing jquery, change this to Cowboy.debounce
filter_input.addEventListener('keyup', $.debounce(250, do_filter));
