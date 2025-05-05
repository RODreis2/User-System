// Hamburger Menu Toggle
document.addEventListener('DOMContentLoaded', () => {
    const hamburger = document.querySelector('.hamburger');
    const navLinks = document.querySelector('.nav-links');

    hamburger.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });

    // Close mobile menu when clicking on a link
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
            navLinks.classList.remove('active');
        });
    });
});

// Handle file input for product images (limit to 5)
document.addEventListener('DOMContentLoaded', () => {
    const fileInput = document.getElementById('product_images');
    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 5) {
                alert('Você pode enviar no máximo 5 imagens.');
                e.target.value = '';
            }
        });
    }
});