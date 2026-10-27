const pptxgen = require('pptxgenjs');
const path = require('path');

// Load html2pptx from the skill directory
const html2pptx = require(path.join(
  process.env.HOME,
  '.bob/skills/pptx/scripts/html2pptx.js'
));

const SLIDES_DIR = path.join(__dirname, 'nhi-slides');
const OUTPUT = path.join(__dirname, 'NHI-Security-Supply-Chain.pptx');

async function build() {
  const pptx = new pptxgen();
  pptx.layout = 'LAYOUT_16x9';
  pptx.title = 'NHI Security Threats in Software Supply Chains';
  pptx.author = 'Security Intelligence';
  pptx.subject = 'Non-Human Identity Supply Chain Security';

  const slides = [
    'slide01.html', // Title
    'slide02.html', // Executive Summary
    'slide03.html', // What Are NHIs
    'slide04.html', // 5-Stage Overview
    'slide05.html', // Stage 1: SCM
    'slide06.html', // Stage 3: CI/CD
    'slide07.html', // Stage 5: Runtime
    'slide08.html', // Breach Timeline
    'slide09.html', // Case Study: SolarWinds
    'slide10.html', // Case Study: Codecov & CircleCI
    'slide11.html', // Threat Actors TTPs
    'slide12.html', // Top 5 Attack Vectors
    'slide13.html', // Secret Sprawl Patterns
    'slide14.html', // Frameworks & Tools
    'slide15.html', // Key Takeaways
  ];

  for (const filename of slides) {
    const htmlFile = path.join(SLIDES_DIR, filename);
    console.log(`Converting ${filename}...`);
    await html2pptx(htmlFile, pptx);
  }

  await pptx.writeFile({ fileName: OUTPUT });
  console.log(`\nPresentation saved: ${OUTPUT}`);
}

build().catch(err => {
  console.error('Build failed:', err.message);
  process.exit(1);
});
