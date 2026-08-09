function matrixRain(glyphs, alpha) {
    const canvas = document.getElementById('bg');
    const ctx = canvas.getContext('2d');
    let W, H, cols, drops;
    const resize = () => {
        W = canvas.width = innerWidth;
        H = canvas.height = innerHeight;
        cols = Math.floor(W / 18);
        drops = Array(cols).fill(0).map(() => Math.random() * H);
    };
    resize();
    addEventListener('resize', resize);
    (function draw() {
        ctx.fillStyle = 'rgba(10,10,12,0.12)';
        ctx.fillRect(0, 0, W, H);
        ctx.fillStyle = `rgba(249,168,212,${alpha})`;
        ctx.font = '13px monospace';
        for (let i = 0; i < cols; i++) {
            ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * 18, drops[i]);
            if (drops[i] > H && Math.random() > 0.975) drops[i] = 0;
            drops[i] += 1.2;
        }
        requestAnimationFrame(draw);
    })();
}