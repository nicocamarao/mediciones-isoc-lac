const canvas = document.getElementById('game');
const ctx = canvas.getContext('2d');

const ground = 350;
const mario = {
  x: 50,
  y: ground - 40,
  vx: 0,
  vy: 0,
  w: 40,
  h: 40,
  onGround: false
};

const keys = { left:false, right:false };
const speed = 3;
const gravity = 0.5;
const jumpStrength = -10;

function handleKey(e, down) {
  if (e.code === 'ArrowLeft') keys.left = down;
  if (e.code === 'ArrowRight') keys.right = down;
  if ((e.code === 'Space' || e.code === 'ArrowUp') && down && mario.onGround) {
    mario.vy = jumpStrength;
    mario.onGround = false;
  }
}

document.addEventListener('keydown', e => handleKey(e, true));
document.addEventListener('keyup', e => handleKey(e, false));

function update() {
  if (keys.left) mario.vx = -speed;
  else if (keys.right) mario.vx = speed;
  else mario.vx = 0;

  mario.vy += gravity;
  mario.x += mario.vx;
  mario.y += mario.vy;

  if (mario.y + mario.h >= ground) {
    mario.y = ground - mario.h;
    mario.vy = 0;
    mario.onGround = true;
  }
}

function draw() {
  ctx.clearRect(0,0,canvas.width,canvas.height);

  // ground
  ctx.fillStyle = '#3c511e';
  ctx.fillRect(0, ground, canvas.width, canvas.height - ground);

  // mario
  ctx.fillStyle = '#ff0000';
  ctx.fillRect(mario.x, mario.y, mario.w, mario.h);
}

function loop() {
  update();
  draw();
  requestAnimationFrame(loop);
}

loop();
