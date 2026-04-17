---
layout: training-page
title: "Adversarial ML Overview — Red Team Academy"
module: "AI Agents & Offensive AI"
tags:
  - adversarial-ml
  - evasion-attacks
  - poisoning
  - model-extraction
  - mitre-atlas
  - ai-red-team
  - foolbox
page_key: "ai-agents-adversarial-ml"
render_with_liquid: false
---

# Adversarial ML Overview

Machine learning systems are increasingly embedded in security-critical infrastructure — physical access control, network anomaly detection, email filtering, endpoint detection, fraud prevention. As red teamers, understanding how to probe, fool, and corrupt these systems is essential both for testing their resilience and for anticipating how adversaries will use ML-evasion as an offensive technique. This page maps the adversarial ML attack taxonomy and connects it to practical red team scenarios.

---

## Attack Taxonomy

Adversarial ML attacks are classified along two primary dimensions: **when** the attack occurs (relative to training) and **what** the attacker controls.

### Evasion Attacks (Test-Time)

Evasion attacks operate at inference time — the model is already trained and deployed. The attacker crafts inputs that cause misclassification without altering the model itself.

| Attack | Target | Goal |
|--------|-------|------|
| FGSM | Image/text classifiers | Single-step misclassification |
| PGD | Image classifiers | Stronger iterative evasion |
| CW | Image classifiers | High-confidence targeted attack |
| Patch attacks | Object detectors (YOLO) | Physical adversarial objects |
| Transfer attacks | Black-box models | Use surrogate model gradients |

**MITRE ATLAS Technique**: AML.T0015 — Evade ML Model

### Poisoning Attacks (Train-Time)

Poisoning attacks modify the training data to corrupt model behavior:

| Attack | Mechanism | Effect |
|--------|---------|--------|
| Clean-label poisoning | Add poisoned samples with correct labels | Model learns wrong decision boundary |
| Backdoor / Trojan | Insert trigger pattern in poisoned samples | Trigger causes targeted misclassification |
| Model inversion | Reconstruct training data from model | Privacy breach |
| Membership inference | Determine if sample was in training set | Privacy breach |

**MITRE ATLAS Technique**: AML.T0020 — Poison Training Data

### Model Extraction

Model extraction (model stealing) recovers a functional approximation of the target model by querying it with many inputs and observing outputs:

```python
# Model extraction via black-box queries
import numpy as np
from sklearn.tree import DecisionTreeClassifier

def extract_model(target_api, n_queries=10000):
    """Query target API to build surrogate model"""
    # Generate diverse query inputs
    X_queries = np.random.uniform(-1, 1, size=(n_queries, feature_dim))
    
    # Query target
    y_labels = []
    for x in X_queries:
        response = target_api.predict(x.tolist())  # API call
        y_labels.append(response["label"])
    
    # Train surrogate
    surrogate = DecisionTreeClassifier(max_depth=10)
    surrogate.fit(X_queries, y_labels)
    return surrogate
```

**MITRE ATLAS Technique**: AML.T0040 — ML Model Inference API Access

### Inference Attacks (Privacy)

- **Membership inference**: does a specific sample appear in the training set?
  - Attack: train shadow models, build classifier on shadow model confidence scores
- **Attribute inference**: infer sensitive attributes of training data
- **Model inversion**: given model access, reconstruct training examples
  - Risk: models trained on faces can be inverted to approximate training photos

---

## Why Red Teamers Need to Know Adversarial ML

### CV-Based Physical Security

Enterprise perimeters increasingly rely on CV for:

| System | Typical Model | Attack Surface |
|--------|-------------|---------------|
| Badge/face recognition | CNN classifier | Adversarial face makeup, infrared LEDs |
| Perimeter cameras | Object detector (YOLO) | Adversarial patches on clothing |
| License plate readers | OCR classifier | Adversarial plate covers |
| Parcel X-ray scanners | Object detector | Adversarial 3D-printed inserts |
| Crowd density | Scene classifier | Adversarial printed backgrounds |

**Physical penetration test consideration**: An adversarial patch (printable sticker) worn on a t-shirt can cause a YOLO-based perimeter camera to classify the wearer as "background" or "tree" rather than "person" — causing the alert system to miss an intruder.

### UEBA (User and Entity Behavior Analytics)

UEBA systems use ML to detect anomalous behavior. Red team evasion:

```
Goal: blend into normal behavior profile
Technique: gradient-free attack against behavioral baseline

1. Enumerate UEBA vendor (Varonis, Securonix, Splunk UEBA)
2. Understand the features it tracks (logon times, access patterns, data volume)
3. Slow down data exfiltration to match normal user rates
4. Use legitimate business applications for C2 (LOLBins)
5. Time activities to match user's historical patterns
```

This is the practical application of adversarial ML thinking without sophisticated attacks — understanding the model's features and staying within the "normal" distribution.

### Spam Filters and Email Security

Adversarial techniques against ML-based email security:

```python
# Text-based evasion of ML spam classifier
# Technique: character substitution that preserves human readability
# but changes token-level features

def evade_spam_filter(malicious_text):
    # Unicode homoglyphs: 'а' (Cyrillic) looks like 'a' (Latin)
    substitutions = {
        'a': 'а',   # Cyrillic а
        'e': 'е',   # Cyrillic е
        'o': 'о',   # Cyrillic о
        'p': 'р',   # Cyrillic р
        'c': 'с',   # Cyrillic с
    }
    evaded = ""
    for char in malicious_text:
        evaded += substitutions.get(char, char)
    return evaded

# "Click here to claim your prize" → "Сliсk hеrе tо сlаim уоur рrizе"
# Human readable, different tokens to ML model
```

### WAF ML Engines

ModSecurity with ML backends and commercial WAFs use ML scoring:

```
Bypass approaches:
1. Parameter encoding variations (%%32%65 for ../  )
2. Case randomization (SeLeCt instead of SELECT)
3. HTTP parameter pollution (same param repeated)
4. Semantic-preserving SQL transformation
   → SELECT 1 FROM users WHERE id=1  
   → SElect/**/ 1 fROm users wHerE id = 0x31

These work because ML WAF models generalize from training samples
— inputs that look different from training get misclassified as benign
```

---

## MITRE ATLAS Framework

MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems) is the adversarial ML analog to ATT&CK.

### Key ATLAS Techniques

| ID | Name | Phase | Description |
|----|------|-------|-------------|
| AML.T0002 | Acquire Public ML Artifacts | Reconnaissance | Download public models/datasets |
| AML.T0004 | Create Proxy ML Model | Resource Dev | Train surrogate for attacks |
| AML.T0012 | Valid Accounts | Initial Access | Compromise ML training pipeline accounts |
| AML.T0015 | Evade ML Model | Defense Evasion | Craft adversarial inputs |
| AML.T0016 | Obtain Capabilities | Resource Dev | Acquire adversarial ML tooling |
| AML.T0018 | Backdoor ML Model | Persistence | Insert backdoor in model weights |
| AML.T0019 | Publish Poisoned Datasets | Impact | Poison public training data |
| AML.T0020 | Poison Training Data | Impact | Corrupt training pipeline |
| AML.T0025 | Exfiltrate Via ML Inference | Exfiltration | Use model API for data exfil |
| AML.T0031 | Erode ML Model Integrity | Impact | Reduce model accuracy |
| AML.T0040 | ML Model Inference API | Collection | Enumerate model via API |
| AML.T0043 | Craft Adversarial Data | Defense Evasion | FGSM/PGD adversarial examples |

---

## Threat Model: Attacker Capabilities

### White-Box (Full Access)

Attacker has:
- Model architecture
- Model weights
- Training data (or distribution)
- Gradient access

**Most powerful**: can compute exact gradients to craft adversarial examples, invert the model, or perform membership inference with high accuracy.

**Real-world scenario**: insider threat, compromised ML infrastructure, open-source model

### Gray-Box (Partial Access)

Attacker has:
- Model outputs (confidence scores)
- Knowledge of model family (e.g., "it's a CNN")
- No direct gradient access

**Techniques**: transfer attacks (use similar open-source model), score-based black-box optimization (CMA-ES, NES)

### Black-Box (Output Only)

Attacker has:
- Hard labels only (class name, no confidence)
- API-rate-limited

**Techniques**: decision-based attacks (Boundary Attack, HopSkipJump), model extraction via queries

```python
# Black-box boundary attack (sklearn-compatible interface)
from art.attacks.evasion import BoundaryAttack
from art.estimators.classification import BlackBoxClassifier

# Wrap target API as ART classifier
def target_predict(x):
    # Call external API with batch of inputs
    results = []
    for sample in x:
        r = api_call(sample.tolist())
        results.append(r["probabilities"])
    return np.array(results)

classifier = BlackBoxClassifier(
    predict_fn=target_predict,
    input_shape=(224, 224, 3),
    nb_classes=1000
)

attack = BoundaryAttack(estimator=classifier, targeted=False)
adversarial = attack.generate(x=original_image)
```

---

## Tools

### Foolbox

Python framework for adversarial attacks, supporting many model frameworks:

```python
import foolbox as fb
import torch

# Load model
model = torchvision.models.resnet50(pretrained=True).eval()
preprocessing = dict(mean=[0.485, 0.456, 0.406], std=[0.229, 0.224, 0.225], axis=-3)
fmodel = fb.PyTorchModel(model, bounds=(0, 1), preprocessing=preprocessing)

# FGSM attack
attack = fb.attacks.FGSM()
images, labels = fb.utils.samples(fmodel, dataset="imagenet", batchsize=4)
epsilons = [0.01, 0.03, 0.1]  # Perturbation magnitude
_, advs, success = attack(fmodel, images, labels, epsilons=epsilons)
print(f"Attack success rate: {success.float().mean():.2%}")

# PGD attack
pgd = fb.attacks.PGD()
_, advs_pgd, success_pgd = pgd(fmodel, images, labels, epsilons=[0.03])
```

### IBM ART (Adversarial Robustness Toolbox)

Comprehensive framework supporting attacks AND defenses:

```python
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent, CarliniL2Method
from art.estimators.classification import PyTorchClassifier
import torch.nn as nn

# Wrap model for ART
classifier = PyTorchClassifier(
    model=model,
    loss=nn.CrossEntropyLoss(),
    optimizer=optimizer,
    input_shape=(3, 224, 224),
    nb_classes=1000
)

# FGSM
fgsm = FastGradientMethod(estimator=classifier, eps=0.05)
x_adv = fgsm.generate(x=x_test)

# PGD (stronger iterative)
pgd = ProjectedGradientDescent(estimator=classifier, eps=0.05, eps_step=0.01, max_iter=40)
x_adv_pgd = pgd.generate(x=x_test)

# CW (strongest, targeted)
cw = CarliniL2Method(classifier=classifier, targeted=True, max_iter=100)
x_adv_cw = cw.generate(x=x_test, y=target_label)
```

### CleverHans

Google Brain's adversarial example library (TensorFlow):

```python
import tensorflow as tf
from cleverhans.tf2.attacks.fast_gradient_method import fast_gradient_method

# FGSM in TF2
@tf.function
def fgsm_attack(model, x, y, eps=0.03):
    with tf.GradientTape() as tape:
        tape.watch(x)
        logits = model(x)
        loss = tf.nn.sparse_softmax_cross_entropy_with_logits(labels=y, logits=logits)
    grad = tape.gradient(loss, x)
    signed_grad = tf.sign(grad)
    x_adv = x + eps * signed_grad
    x_adv = tf.clip_by_value(x_adv, 0, 1)
    return x_adv
```

---

## Defense Landscape

Understanding defenses helps red teamers build more robust attacks:

| Defense | Mechanism | Bypass |
|---------|----------|--------|
| Adversarial training | Train on adversarial examples | Stronger attacks (adaptive) |
| Input preprocessing | Denoising, JPEG compression | Differentiable preprocessing, Expectation over Transformation |
| Certified defenses (Randomized Smoothing) | Provable robustness via Gaussian noise | Effective for small ε, fails at large ε |
| Ensemble defenses | Average predictions from multiple models | Transfer attacks across ensemble |
| Feature squeezing | Reduce input dimensionality | Higher-epsilon attacks |
| Model distillation | Train on soft labels | White-box still works |
| Detector models | Separate classifier for adversarial inputs | Adversarial examples for the detector |

```python
# Bypass input preprocessing via Expectation over Transformation (EOT)
# If defense: JPEG compress input before classifying
# Attack: optimize adversarial perturbation THROUGH the JPEG compression

from art.defences.preprocessor import JpegCompression

# Wrap classifier with preprocessor
defended_classifier = PyTorchClassifier(
    model=model,
    preprocessing_defences=[JpegCompression(clip_values=(0, 255), quality=75)],
    ...
)

# Attack the defended classifier directly — ART handles the gradient through defense
pgd = ProjectedGradientDescent(estimator=defended_classifier, eps=16, eps_step=2, max_iter=50)
x_adv = pgd.generate(x=x_test)
# These adversarial examples survive JPEG compression
```
