let sc_candidates_json_url = $("#sc-candidates-json-url").attr("href");

let sc_candidates_source = new Bloodhound({
    datumTokenizer: Bloodhound.tokenizers.whitespace,
    prefetch: sc_candidates_json_url,
    queryTokenizer: Bloodhound.tokenizers.whitespace
});

$('.sc-candidate-typeahead').typeahead({
    classNames: {
        dataset: 'list-group',
        suggestion: 'list-group-item list-group-item-action list-group-item-dark'
    },
    highlight: true
}, {
    limit: 10,
    name: "sc-candidates-source",
    source: sc_candidates_source
});
