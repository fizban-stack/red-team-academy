---
layout: training-page
title: "Adversarial Examples & CV Evasion — Red Team Academy"
module: "AI Agents & Offensive AI"
tags:
  - adversarial-examples
  - cv-evasion
  - fgsm
  - pgd
  - yolo-attack
  - physical-adversarial
  - facial-recognition-bypass
page_key: "ai-agents-model-evasion"
render_with_liquid: false
---

# Adversarial Examples & CV Evasion

Adversarial examples are inputs to machine learning models that are intentionally crafted to cause misclassification. For image classifiers and object detectors used in physical security — surveillance cameras, facial recognition access control, badge readers, perimeter detection — adversarial examples can be printed, worn, or displayed to fool the deployed model while remaining visually legitimate to humans. This page covers the theory and practical techniques from gradient-based attacks to physical deployments.

---

## Physical Adversarial Examples

The most operationally relevant adversarial attacks for physical red teams are those that can be instantiated in the real world — printed on paper, applied as stickers, or incorporated into clothing.

### Adversarial Patches

An adversarial patch is a localized image region that, when present anywhere in the frame, causes the detector to misclassify or fail to detect objects.

**How they work:**
```python
import torch
import torch.nn as nn
from torchvision import transforms

def train_adversarial_patch(model, target_class, patch_size=(50, 50), n_iter=1000):
    """
    Train an adversarial patch that causes any image containing it
    to be classified as target_class
    """
    # Initialize random patch
    patch = torch.rand(3, *patch_size, requires_grad=True)
    optimizer = torch.optim.Adam([patch], lr=0.01)
    
    criterion = nn.CrossEntropyLoss()
    
    for iteration in range(n_iter):
        # Sample random background images from training set
        bg_images = sample_batch(batch_size=16)
        
        # Apply patch at random locations in each image
        patched = apply_patch_randomly(bg_images, patch, patch_size)
        
        # Forward pass
        logits = model(patched)
        
        # Loss: maximize probability of target class
        target = torch.full((16,), target_class, dtype=torch.long)
        loss = criterion(logits, target)
        
        # Backprop through the entire model into the patch pixels
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        # Clamp to valid image range
        patch.data.clamp_(0, 1)
        
        if iteration % 100 == 0:
            print(f"Iter {iteration}: loss={loss.item():.4f}")
    
    return patch.detach()

def apply_patch_randomly(images, patch, patch_size):
    """Apply patch at random position in each image"""
    result = images.clone()
    for i in range(images.shape[0]):
        h, w = images.shape[2], images.shape[3]
        ph, pw = patch_size
        # Random position
        y = torch.randint(0, h - ph, (1,)).item()
        x = torch.randint(0, w - pw, (1,)).item()
        result[i, :, y:y+ph, x:x+pw] = patch
    return result
```

**Physical deployment:**
1. Print the optimized patch on paper or fabric (inkjet prints are sufficient for many attacks)
2. Wear or carry the patch within camera view
3. Verify effectiveness by testing against the actual deployed model or a proxy

**Documented adversarial clothing projects:**
- Adversarial t-shirts printed with patterns that cause pedestrian detectors to fail (stop-sign class misclassification)
- Hats with printed patterns causing facial recognition to classify wearers as different individuals
- Glasses frames with InfraRed LEDs (not visible to humans, visible to NIR cameras) that interfere with face recognition enrollment distance

---

## FGSM: Fast Gradient Sign Method

FGSM (Goodfellow et al., 2014) is the foundational gradient-based adversarial attack. It computes the gradient of the loss with respect to the input image and adds a small perturbation in the direction that increases the loss.

### Mathematical Formulation

```
x_adv = x + ε × sign(∇_x J(θ, x, y))

Where:
  x     = original input
  ε     = perturbation magnitude (typically 0.01 - 0.1 for [0,1] images)
  J     = loss function (cross-entropy)
  θ     = model parameters
  y     = true label
  ∇_x   = gradient with respect to x
```

### PyTorch Implementation

```python
import torch
import torch.nn.functional as F

def fgsm_attack(model, image, label, epsilon=0.03):
    """
    Fast Gradient Sign Method attack
    
    Args:
        model: PyTorch model (in eval mode)
        image: input tensor [1, C, H, W], normalized to [0, 1]
        label: ground truth label (LongTensor)
        epsilon: perturbation magnitude
    
    Returns:
        adversarial image tensor
    """
    # Enable gradient tracking on input
    image.requires_grad = True
    
    # Forward pass
    output = model(image)
    
    # Compute loss w.r.t. true label
    loss = F.cross_entropy(output, label)
    
    # Backward pass — compute gradient w.r.t. image
    model.zero_grad()
    loss.backward()
    
    # Collect gradient sign
    grad_sign = image.grad.data.sign()
    
    # Create adversarial image
    adversarial = image + epsilon * grad_sign
    
    # Clamp to valid image range
    adversarial = torch.clamp(adversarial, 0, 1)
    
    return adversarial.detach()

# Example usage
model = torchvision.models.resnet50(pretrained=True).eval()
image = preprocess(PIL.Image.open("cat.jpg")).unsqueeze(0)
label = torch.tensor([281])  # ImageNet "tabby cat"

adv_image = fgsm_attack(model, image, label, epsilon=0.03)
pred = model(adv_image).argmax().item()
print(f"Original: cat (281) → Adversarial prediction: {imagenet_labels[pred]}")
```

**FGSM characteristics:**
- Single forward + backward pass → very fast
- Relatively weak (single step)
- ε = 0.01: barely visible perturbation, moderate success
- ε = 0.1: visible noise, high success rate

---

## PGD: Projected Gradient Descent

PGD (Madry et al., 2017) is the iterative version of FGSM — it applies multiple smaller steps and projects back onto the ε-ball after each step, creating much stronger adversarial examples.

### Algorithm

```
x_0 = x + uniform_noise(−ε, ε)  # Random start within ε-ball

For t = 1, ..., T:
    x_t = x_{t-1} + α × sign(∇_x J(θ, x_{t-1}, y))
    x_t = project(x_t, ε-ball around x)  # Keep within L∞ ε constraint
    x_t = clamp(x_t, 0, 1)              # Keep in valid image range
```

```python
def pgd_attack(model, image, label, epsilon=0.03, alpha=0.007, num_iter=40, random_start=True):
    """
    PGD (L∞) adversarial attack
    
    Args:
        epsilon: maximum perturbation (L∞ norm constraint)
        alpha: step size per iteration
        num_iter: number of iterations (more = stronger attack)
        random_start: add random initialization (important for adversarial training bypass)
    """
    if random_start:
        # Random initialization within ε-ball
        delta = torch.empty_like(image).uniform_(-epsilon, epsilon)
        delta = torch.clamp(image + delta, 0, 1) - image
    else:
        delta = torch.zeros_like(image)
    
    delta.requires_grad_(True)
    
    for _ in range(num_iter):
        output = model(image + delta)
        loss = F.cross_entropy(output, label)
        
        loss.backward()
        
        # Step in gradient sign direction
        delta.data = delta + alpha * delta.grad.data.sign()
        
        # Project back to ε-ball (clip)
        delta.data = torch.clamp(delta.data, -epsilon, epsilon)
        
        # Keep in valid image range
        delta.data = torch.clamp(image + delta.data, 0, 1) - image
        
        delta.grad.zero_()
    
    return (image + delta).detach()

# PGD-40 attack (40 iterations)
adv = pgd_attack(model, image, label, epsilon=8/255, alpha=2/255, num_iter=40)
```

**PGD vs FGSM:**
| Property | FGSM | PGD (40 iter) |
|---------|------|--------------|
| Compute cost | ~1x | ~40x |
| Success rate | 40-70% | 80-99% |
| Use case | Quick testing | Strong attack, adversarial training |

---

## CW Attack: Carlini-Wagner

The CW attack (Carlini & Wagner, 2017) formulates adversarial example generation as an optimization problem and consistently produces the strongest attacks with the smallest perturbations.

### Formulation (L2 variant)

```
minimize: ||δ||₂² + c × f(x + δ)
subject to: x + δ ∈ [0, 1]

Where f(x') = max(Z(x')[true_class] - max_{i≠true_class} Z(x')[i], -κ)
κ = confidence parameter (higher = more confident misclassification)
Z(x') = pre-softmax logits
```

```python
from art.attacks.evasion import CarliniL2Method
from art.estimators.classification import PyTorchClassifier

# Wrap model
classifier = PyTorchClassifier(
    model=model,
    loss=nn.CrossEntropyLoss(),
    optimizer=optimizer,
    input_shape=(3, 224, 224),
    nb_classes=1000,
    clip_values=(0.0, 1.0)
)

# CW L2 attack
cw = CarliniL2Method(
    classifier=classifier,
    targeted=True,          # Targeted: force classification as specific class
    confidence=0.0,         # κ=0: just cross the decision boundary
    learning_rate=0.01,     # Optimization learning rate
    max_iter=100,           # Optimization iterations
    initial_const=1e-2      # c initial value
)

# Target: classify "cat" as "dog"
target_class = 207  # ImageNet "golden retriever"
y_target = np.eye(1000)[target_class].reshape(1, -1)

x_adv = cw.generate(x=x_test, y=y_target)
print(f"L2 distance: {np.linalg.norm(x_adv - x_test):.4f}")
print(f"Adversarial class: {model.predict(x_adv).argmax()}")  # Should be 207
```

**CW characteristics:**
- Produces minimum-distortion adversarial examples
- L2 norm optimization: perturbation is spread uniformly (less visible than L∞)
- Targeted misclassification: force any specific class
- Slower than FGSM/PGD — used for generating high-quality adversarial training data

---

## Black-Box Attacks

When model gradients are unavailable (API-only access), gradient-free attacks are required.

### ZOO (Zeroth Order Optimization)

ZOO estimates gradients via finite differences without white-box model access:

```python
# ZOO attack — estimates gradient via coordinate-wise finite differences
# Δf/Δx_i ≈ (f(x + h*e_i) - f(x - h*e_i)) / (2h)

from art.attacks.evasion import ZooAttack

zoo = ZooAttack(
    classifier=black_box_classifier,
    confidence=0.0,
    targeted=False,
    learning_rate=1e-1,
    max_iter=200,
    binary_search_steps=10,
    initial_const=1e-3,
    nb_parallel=8,         # Parallel gradient estimates
    variable_h=False
)

x_adv = zoo.generate(x=x_test[:1])
```

### NES-Based Attacks (Natural Evolutionary Strategies)

```python
def nes_attack(query_fn, x, true_label, epsilon=0.05, n_samples=100, sigma=0.01, lr=0.01, n_iter=200):
    """
    Black-box attack using Natural Evolutionary Strategies gradient estimation
    
    query_fn: function that takes image array, returns class probabilities
    """
    x_adv = x.copy()
    
    for i in range(n_iter):
        # Sample perturbations
        noise = np.random.randn(n_samples, *x.shape)
        
        # Estimate gradient via NES
        # E[f(x + σu)u] ≈ gradient of E[f(x + σu)]
        scores = []
        for j in range(n_samples):
            probs_pos = query_fn(np.clip(x_adv + sigma * noise[j], 0, 1))
            probs_neg = query_fn(np.clip(x_adv - sigma * noise[j], 0, 1))
            # Use log probability of true class as objective
            scores.append(
                np.log(probs_pos[true_label] + 1e-8) - 
                np.log(probs_neg[true_label] + 1e-8)
            )
        
        # Gradient estimate
        grad_est = np.mean([s * n for s, n in zip(scores, noise)], axis=0) / (2 * sigma)
        
        # Update (maximize loss = increase grad, then project)
        x_adv = x_adv + lr * np.sign(grad_est)
        x_adv = np.clip(x_adv, x - epsilon, x + epsilon)
        x_adv = np.clip(x_adv, 0, 1)
        
        if i % 20 == 0:
            pred = query_fn(x_adv).argmax()
            print(f"Iter {i}: prediction = {pred} (target ≠ {true_label})")
            if pred != true_label:
                print("Success!")
                break
    
    return x_adv
```

---

## Physical Realizability

Translating digital adversarial examples to physical objects involves several practical constraints:

### Printable Patch Considerations

```python
# Ensure patch uses only printable colors (in sRGB gamut)
def project_to_printable(patch):
    """Project adversarial patch to colors achievable with standard ink"""
    # CMYK gamut approximation: clip to slightly reduced RGB range
    patch = torch.clamp(patch, 0.05, 0.95)
    return patch

# Rotation and scale invariance training (for physical placement uncertainty)
def augment_patch_placement(images, patch, n_transforms=5):
    """Train patch to be robust to rotation, scale, and lighting changes"""
    augmented_images = []
    for _ in range(n_transforms):
        angle = torch.FloatTensor(1).uniform_(-30, 30)
        scale = torch.FloatTensor(1).uniform_(0.8, 1.2)
        brightness = torch.FloatTensor(1).uniform_(0.5, 1.5)
        
        transformed_patch = torchvision.transforms.functional.rotate(patch, angle.item())
        transformed_patch = transformed_patch * brightness.item()
        transformed_patch = torch.clamp(transformed_patch, 0, 1)
        
        augmented = apply_patch_randomly(images, transformed_patch, patch.shape[-2:])
        augmented_images.append(augmented)
    
    return torch.cat(augmented_images, dim=0)
```

### Adversarial Glasses (CV Dazzle)

CV Dazzle makeup patterns (Harvey, 2010) exploit face detector feature extraction:

```
Known effective patterns:
1. High-contrast asymmetric color blocks across the nose bridge
   → Disrupts face detector's assumption of bilateral symmetry
2. Hair covering one eye
   → Removes eye landmarks required for face confirmation
3. High-contrast geometric shapes painted on face
   → Disrupts Viola-Jones Haar cascade feature response

Modern DNN-based detectors require adversarially optimized patterns (not just CV Dazzle):
- Optimize perturbation via PGD with face detector loss
- Must be applied consistently under real lighting conditions
```

### InfraRed LED Attack on Near-IR Cameras

```
Many face recognition systems use near-infrared (NIR) cameras:
- Avoids ambient lighting variability
- Works in darkness
- Face recognition training uses NIR images

Attack: IR LED glasses
- Embed 850nm IR LEDs in glasses frame
- LEDs are invisible to humans, visible to NIR cameras
- Bright IR emission overexposures the face region in NIR image
- Causes face detection failure or substitutes IR pattern for face features

Components:
- 850nm IR LEDs (common, cheap)
- Small LiPo battery (fits in glasses frame)
- Current-limiting resistors
- Works within ~1-2m of camera
```

---

## Practical: Evading a YOLO Object Detector with Adversarial Patch

### Setup

```python
import torch
import numpy as np
from ultralytics import YOLO
from PIL import Image

# Load YOLOv8 model (simulating deployed perimeter camera model)
model = YOLO("yolov8n.pt")  # Or custom-trained security model

class YOLOWrapper(torch.nn.Module):
    """Wrap YOLO for gradient computation"""
    def __init__(self, yolo_model):
        super().__init__()
        self.model = yolo_model.model
    
    def forward(self, x):
        return self.model(x)

# Training adversarial patch
def train_yolo_patch(yolo_wrapper, person_class_id=0, patch_size=100, n_iter=2000):
    patch = torch.rand(3, patch_size, patch_size, requires_grad=True)
    optimizer = torch.optim.Adam([patch], lr=0.02)
    
    person_images = load_person_images(batch_size=8)
    
    for i in range(n_iter):
        batch = person_images.clone()
        # Apply patch to chest area of each person image
        batch = apply_patch_to_persons(batch, patch.clamp(0, 1))
        
        outputs = yolo_wrapper(batch)
        
        # Loss: maximize confidence for non-person or minimize person confidence
        person_conf = extract_person_confidences(outputs, class_id=person_class_id)
        loss = person_conf.mean()  # Minimize person detection confidence
        
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()
        
        if i % 100 == 0:
            print(f"Iter {i}: avg person confidence = {person_conf.mean().item():.4f}")
    
    return patch.detach().clamp(0, 1)

# Generate the patch
patch = train_yolo_patch(YOLOWrapper(model))

# Save for printing
patch_img = (patch.permute(1, 2, 0).numpy() * 255).astype(np.uint8)
Image.fromarray(patch_img).save("adversarial_patch.png")
print("Patch saved — print at 20cm × 20cm and affix to clothing")
```

### Evaluation

```python
# Test patch effectiveness
model_clean = YOLO("yolov8n.pt")

test_images = load_test_set()  # Images of people
patch = torch.load("adversarial_patch.pt")

clean_detections = 0
patched_detections = 0

for img in test_images:
    # Clean image: expect person detected
    result_clean = model_clean(img)
    if any(box.cls == 0 for box in result_clean[0].boxes):
        clean_detections += 1
    
    # Patched image: should fail to detect
    img_patched = apply_patch(img, patch)
    result_patched = model_clean(img_patched)
    if any(box.cls == 0 for box in result_patched[0].boxes):
        patched_detections += 1

print(f"Clean detection rate: {clean_detections/len(test_images):.1%}")
print(f"Patched detection rate: {patched_detections/len(test_images):.1%}")
print(f"Evasion rate: {1 - patched_detections/len(test_images):.1%}")
```

### LiDAR Spoofing Note

Autonomous vehicle and physical security systems increasingly use LiDAR:

```
Physical LiDAR adversarial attacks:
- Laser injection: high-power laser pulses into LiDAR sensor 
  → Inject fake objects at specific positions in point cloud
  → "Remove" real obstacles from LiDAR data
  
Attack surface in enterprise:
- Parking security systems with LiDAR-based vehicle counting
- Warehouse robots using LiDAR navigation
- Perimeter sensors using LiDAR tripwires

Not commonly accessible attack — requires line-of-sight and specific laser equipment
Documented in research: Sun et al. 2020, "Towards Robust LiDAR-based Perception"
```
