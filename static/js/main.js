// Main JavaScript for Unquantifiable Uncertainty

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Add current year to footer
    document.querySelector('footer .container').innerHTML = 
        document.querySelector('footer .container').innerHTML.replace('{{ now.year }}', new Date().getFullYear());

    // Add nl2br filter functionality for templates
    // This is handled server-side in Flask, but adding a fallback here
    document.querySelectorAll('.opinion-content').forEach(function(element) {
        if (!element.innerHTML.includes('<br>') && element.innerHTML.includes('\n')) {
            element.innerHTML = element.innerHTML.replace(/\n/g, '<br>');
        }
    });

    // Fade out flash messages after 5 seconds
    setTimeout(function() {
        document.querySelectorAll('.alert').forEach(function(alert) {
            const bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // Add active class to current nav item
    const currentLocation = window.location.pathname;
    document.querySelectorAll('.navbar-nav .nav-link').forEach(function(link) {
        if (link.getAttribute('href') === currentLocation) {
            link.classList.add('active');
        }
    });
});

// Confirmation for delete actions
function confirmDelete(event, message) {
    if (!confirm(message || 'Are you sure you want to delete this item?')) {
        event.preventDefault();
        return false;
    }
    return true;
}

// Utility function to format dates
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric'
    });
}
