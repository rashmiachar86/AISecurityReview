"""
Generates NHI Code Review Decision Tree as a PNG.
"""
from PIL import Image, ImageDraw, ImageFont
import math

# ── Canvas ──────────────────────────────────────────────────────────────────
W, H = 2000, 2050
BG        = (13, 27, 42)      # #0D1B2A  dark navy
CARD_DARK = (21, 34, 50)      # #152232
CARD_MID  = (27, 42, 59)      # #1B2A3B
BLUE      = (27, 108, 168)    # #1B6CA8
RED       = (192, 57, 43)     # #C0392B
GREEN     = (39, 174, 96)     # #27AE60
AMBER     = (230, 126, 34)    # #E67E22
WHITE     = (255, 255, 255)
LIGHT     = (170, 183, 184)   # #AAB7B8
MUTED     = (85, 98, 112)     # #556270
CONNECTOR = (55, 72, 90)      # arrow lines

img  = Image.new("RGB", (W, H), BG)
d    = ImageDraw.Draw(img)

# ── Fonts ────────────────────────────────────────────────────────────────────
def font(size, bold=False):
    candidates = [
        "/System/Library/Fonts/Helvetica.ttc",
        "/System/Library/Fonts/Arial.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default()

F_TITLE   = font(34, bold=True)
F_HEAD    = font(20, bold=True)
F_BODY    = font(17)
F_SMALL   = font(14)
F_MICRO   = font(13)
F_LABEL   = font(15, bold=True)

# ── Helpers ──────────────────────────────────────────────────────────────────
def rect(x, y, w, h, fill, radius=10, border_color=None, border_w=2):
    d.rounded_rectangle([x, y, x+w, y+h], radius=radius, fill=fill)
    if border_color:
        d.rounded_rectangle([x, y, x+w, y+h], radius=radius,
                            outline=border_color, width=border_w)

def text_c(txt, cx, y, fnt, color=WHITE):
    bb = d.textbbox((0,0), txt, font=fnt)
    tw = bb[2]-bb[0]
    d.text((cx - tw//2, y), txt, font=fnt, fill=color)

def text_l(txt, x, y, fnt, color=WHITE, max_w=None):
    if max_w is None:
        d.text((x, y), txt, font=fnt, fill=color)
        return
    # word-wrap
    words = txt.split()
    line, lines = "", []
    for w in words:
        test = (line + " " + w).strip()
        bb = d.textbbox((0,0), test, font=fnt)
        if bb[2]-bb[0] <= max_w:
            line = test
        else:
            if line: lines.append(line)
            line = w
    if line: lines.append(line)
    lh = fnt.size + 5
    for i, ln in enumerate(lines):
        d.text((x, y + i*lh), ln, font=fnt, fill=color)
    return len(lines) * lh

def arrow_down(cx, y1, y2, color=CONNECTOR, thick=2):
    d.line([(cx, y1), (cx, y2-8)], fill=color, width=thick)
    d.polygon([(cx-6, y2-8), (cx+6, y2-8), (cx, y2)], fill=color)

def arrow_right(x1, cy, x2, color=CONNECTOR, thick=2):
    d.line([(x1, cy), (x2-8, cy)], fill=color, width=thick)
    d.polygon([(x2-8, cy-5), (x2-8, cy+5), (x2, cy)], fill=color)

def yes_badge(x, y):
    rect(x, y, 36, 22, GREEN, radius=4)
    text_c("YES", x+18, y+3, F_MICRO, WHITE)

def no_badge(x, y):
    rect(x, y, 30, 22, MUTED, radius=4)
    text_c("NO", x+15, y+3, F_MICRO, WHITE)

# ── Title bar ────────────────────────────────────────────────────────────────
rect(0, 0, W, 70, CARD_MID)
d.rectangle([0, 0, 6, 70], fill=BLUE)
d.rectangle([6, 0, 10, 70], fill=RED)
text_c("NHI Code Review — Decision Tree", W//2, 12, F_TITLE, WHITE)
text_c("Check every PR diff against these questions in order", W//2, 48, F_SMALL, LIGHT)

# ═══════════════════════════════════════════════════════════════════════════════
# Layout constants
# ═══════════════════════════════════════════════════════════════════════════════
QW   = 740   # question box width
QH   = 68    # question box height
AW   = 620   # action box width
AH   = 80
# Left-align question column; right column gets remaining space
MARGIN = 50
CX   = W//2
QX   = MARGIN
action_x_fixed = QX + QW + 80   # fixed start of action column

questions = [
    {
        "q": "Does the diff contain a literal string that looks like a secret?",
        "sub": "API key, token, password, private key, connection string with creds",
        "color": RED,
        "yes_action": [
            ("BLOCK immediately. Treat credential as compromised.", RED),
            ("Ask author to revoke + rotate it, then reference a secrets manager.", LIGHT),
            ("Rotate any already-committed value — history search won't save you.", LIGHT),
        ],
    },
    {
        "q": "Does the diff add or modify a CI/CD workflow file?",
        "sub": ".github/workflows/,  Jenkinsfile,  .gitlab-ci.yml,  .circleci/config.yml",
        "color": AMBER,
        "yes_action": [
            ("Check CI/CD trigger scope, action pinning, and permissions.", AMBER),
            ("Reject pull_request_target without explicit secret restrictions.", LIGHT),
            ("Pin actions to a commit SHA — not a tag.  Scope permissions block.", LIGHT),
        ],
    },
    {
        "q": "Does the diff add or modify a Dockerfile or container definition?",
        "sub": "Dockerfile,  docker-compose.yml,  .dockerignore,  base image changes",
        "color": BLUE,
        "yes_action": [
            ("Check for secrets in ENV / ARG / COPY and image pinning.", BLUE),
            ("No secrets baked into image layers — use multi-stage builds.", LIGHT),
            ("Base image must be digest-pinned (not :latest).  No --privileged.", LIGHT),
        ],
    },
    {
        "q": "Does the diff add or change dependencies?",
        "sub": "package.json,  requirements.txt,  go.mod,  pom.xml,  Gemfile",
        "color": BLUE,
        "yes_action": [
            ("Check version pinning, lock file consistency, install scripts.", BLUE),
            ("Versions must be exact — not ^ or *.  Lock file must be updated.", LIGHT),
            ("Scrutinise any postinstall / prepare scripts for malicious code.", LIGHT),
        ],
    },
    {
        "q": "Does the diff touch Infrastructure-as-Code?",
        "sub": "Terraform .tf / .tfvars,  Helm values,  Kubernetes YAML,  CloudFormation",
        "color": AMBER,
        "yes_action": [
            ("Check IAM scoping, service account settings, metadata service.", AMBER),
            ("No hardcoded credentials.  No wildcard (*) IAM resource policies.", LIGHT),
            ("automountServiceAccountToken: false.  IMDSv2 enforced on EC2.", LIGHT),
        ],
    },
    {
        "q": "Does the diff add new logging, debugging, or error output?",
        "sub": "print(),  log.info(),  console.log(),  exception messages,  raise",
        "color": BLUE,
        "yes_action": [
            ("Check that no secret values can appear in any log line.", BLUE),
            ("Use structured logging — never interpolate credentials into messages.", LIGHT),
            ("Remove all debug-mode credential dumps before merge.", LIGHT),
        ],
    },
    {
        "q": "Does the diff create or modify IAM roles, service accounts, or RBAC?",
        "sub": "aws_iam_role,  ClusterRoleBinding,  ServiceAccount,  azure_role_assignment",
        "color": RED,
        "yes_action": [
            ("Enforce least privilege — document WHY each permission is needed.", RED),
            ("No wildcard (*) resources.  Justify every action in the PR description.", LIGHT),
            ("Prefer OIDC / workload identity over long-lived access keys.", LIGHT),
        ],
    },
]

# ── Compute row heights dynamically (3 action lines + padding) ───────────────
ROW_LINE_H = 23
ACTION_LINES = 3
ACTION_PAD_T = 10
ACTION_PAD_B = 10
AH_REAL = ACTION_PAD_T + ACTION_LINES * ROW_LINE_H + ACTION_PAD_B   # ~99px

Q_PAD = 22          # vertical gap between question rows
ARROW_PAD = 10      # space for NO badge + arrow between rows

# Row height = max(QH, AH_REAL) + gap
ROW_H = max(QH, AH_REAL) + Q_PAD + ARROW_PAD

Y = 90

for i, item in enumerate(questions):
    q_y = Y
    # vertically centre question box within the row height
    q_offset = (AH_REAL - QH) // 2 if AH_REAL > QH else 0
    qbox_y   = q_y + q_offset

    # ── Question box ─────────────────────────────────────────────────────────
    rect(QX, qbox_y, QW, QH, CARD_MID, border_color=item["color"], border_w=3)
    # number badge
    rect(QX+10, qbox_y+10, 38, 38, item["color"], radius=7)
    text_c(str(i+1), QX+29, qbox_y+14, F_HEAD, WHITE)
    # question text (main + sub)
    d.text((QX+58, qbox_y+8),  item["q"],   font=F_LABEL, fill=WHITE)
    d.text((QX+58, qbox_y+36), item["sub"], font=F_MICRO, fill=LIGHT)

    # ── YES badge & horizontal arrow ─────────────────────────────────────────
    yes_mid_y = qbox_y + QH//2
    yes_badge(QX + QW + 8, yes_mid_y - 11)
    arrow_x_start = QX + QW + 48
    arrow_right(arrow_x_start, yes_mid_y, action_x_fixed, color=item["color"], thick=2)

    # ── Action box ───────────────────────────────────────────────────────────
    action_x = action_x_fixed
    rect(action_x, q_y, AW, AH_REAL, CARD_DARK, border_color=item["color"], border_w=2, radius=8)

    # left accent bar
    d.rectangle([action_x, q_y, action_x+4, q_y+AH_REAL], fill=item["color"])

    for li, (ln, col) in enumerate(item["yes_action"]):
        ty = q_y + ACTION_PAD_T + li * ROW_LINE_H
        fnt = F_LABEL if li == 0 else F_SMALL
        d.text((action_x + 16, ty), ln, font=fnt, fill=col)

    # ── NO badge & down arrow to next question ────────────────────────────────
    no_cx   = QX + QW//2          # centre below the question box
    no_top  = qbox_y + QH + 4
    no_badge(no_cx - 15, no_top)

    next_q_y    = q_y + ROW_H
    next_qbox_y = next_q_y + (AH_REAL - QH) // 2 if AH_REAL > QH else next_q_y

    if i < len(questions) - 1:
        arrow_down(no_cx, no_top + 22, next_qbox_y, color=MUTED, thick=2)

    Y = next_q_y

# ── Final OK box ─────────────────────────────────────────────────────────────
OK_Y  = Y + 10
OK_W  = 600
OK_CX = QX + QW//2
rect(OK_CX - OK_W//2, OK_Y, OK_W, 74, (15, 50, 32), border_color=GREEN, border_w=3, radius=12)
text_c("✓  All checks passed — PR is clear to merge", OK_CX, OK_Y+12, F_HEAD, GREEN)
text_c("Run GitLeaks / TruffleHog as the final automated gate", OK_CX, OK_Y+42, F_SMALL, LIGHT)

# ── Footer ────────────────────────────────────────────────────────────────────
FOOT_Y = OK_Y + 96
d.line([(40, FOOT_Y), (W-40, FOOT_Y)], fill=CONNECTOR, width=1)
text_c("NHI Security — Code Review Decision Tree  ·  Source: SCSforAI.md",
       W//2, FOOT_Y+10, F_MICRO, MUTED)

# ── Crop to content ───────────────────────────────────────────────────────────
final_h = FOOT_Y + 42
img = img.crop((0, 0, W, final_h))
img.save("NHI-CodeReview-DecisionTree.png", dpi=(150, 150))
print(f"Saved NHI-CodeReview-DecisionTree.png  ({W}×{final_h})")
