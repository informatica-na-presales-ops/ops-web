function on_change_request_type() {
    const region_envelope = document.getElementById('envelope-region');
    const bug_envelope = document.getElementById('envelope-bug');
    const change_request_envelope = document.getElementById('envelope-change-request');
    switch (this.value) {
        case 'system-down':
            region_envelope.classList.add('show');
            region_envelope.querySelectorAll('input').forEach(function (node) {
                node.required = true;
            });
            bug_envelope.classList.remove('show');
            bug_envelope.querySelectorAll('input,textarea').forEach(function (node) {
                node.required = false;
            });
            change_request_envelope.classList.remove('show');
            change_request_envelope.querySelectorAll('input').forEach(function (node) {
                node.required = false;
            });
            break;
        case 'bug':
            region_envelope.classList.add('show');
            region_envelope.querySelectorAll('input').forEach(function (node) {
                node.required = true;
            });
            bug_envelope.classList.add('show');
            bug_envelope.querySelectorAll('input,textarea').forEach(function (node) {
                node.required = true;
            });
            change_request_envelope.classList.remove('show');
            change_request_envelope.querySelectorAll('input').forEach(function (node) {
                node.required = false;
            });
            break;
        case 'change-request':
            region_envelope.classList.remove('show');
            region_envelope.querySelectorAll('input').forEach(function (node) {
                node.required = false;
            });
            bug_envelope.classList.remove('show');
            bug_envelope.querySelectorAll('input,textarea').forEach(function (node) {
                node.required = false;
            });
            change_request_envelope.classList.add('show');
            change_request_envelope.querySelectorAll('input').forEach(function (node) {
                node.required = true;
            });
            break;
    }
}

document.querySelectorAll('input[name="request-type"]').forEach(function (node) {
    node.addEventListener('change', on_change_request_type);
});
