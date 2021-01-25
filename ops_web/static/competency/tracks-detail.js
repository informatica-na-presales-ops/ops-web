const score_input = document.getElementById('score');

score_input.addEventListener('input', function () {
    score_input.setCustomValidity('');

    if (score_input.value === '') {
        // pass
    } else {
        document.querySelectorAll('[data-score]').forEach(function (el) {
            if (parseInt(el.dataset.score) === parseInt(score_input.value)) {
                console.log('Setting custom validity.');
                score_input.setCustomValidity('This score is already in use by another level.');
            }
        });
    }

    score_input.reportValidity();
});
