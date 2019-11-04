const url_params = new URLSearchParams(window.location.search);

function do_filter (event) {
    if (event && event.keyCode === 27) {
        // [Esc] was pressed
        $(this).val('');
    }
    let query = $('#filter-input').val().toLowerCase();
    let items = $('.filter-candidate');
    if (query === '') {
        items.show();
        url_params.delete('filter');
    } else {
        items.each(function () {
            if (this.getAttribute('data-filter-value').includes(query)) {
                $(this).show();
            } else {
                $(this).hide();
            }
        });
        url_params.set('filter', query);
    }
    window.history.pushState({}, '', `${location.pathname}?${url_params}`);
}

if (url_params.has('filter')) {
    do_filter();
}

$('#filter-input').keyup($.debounce(250, do_filter));
