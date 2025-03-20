# SHA-256 Cryptanalysis using AI & Quantum Randomness  

## 🔬 Researching Keccak-256 security using AI & quantum random generators

🚀 **This project investigates SHA-256 security using AI, procedurally generated data, and quantum random generators.**
My previous research on SHA-256 showed a statistical anomaly in the message scheduler that allows prediction of `w15` values ​​with twice the probability.

---

## 🔑 Features & Methodology

**AI-supported cryptanalysis:** Deep learning models with TensorFlow for pattern recognition in Keccak-256

**Quantum random generator:** Generates high-entropic training data to eliminate overfitting

**Procedurally generated data:** Gigabyte-wide data sets for robust training data generation and prevention of overfitting, the training data set includes 300 million hashes

**Cython & low-level C optimization:** Performance boost for extremely high hash rate processing

**SHA-256 findings as a basis:** Extension of the successful SHA-256 analysis to Keccak-256

---


## 📊 First findings from SHA-256 research

**Message Scheduler Anomaly:** The `w15` values ​​can be predicted with **double probability** under certain conditions.

**AI finds correlations:** My models show that there are hidden patterns in SHA-256 that classical cryptography methods do not discover.

---

## 📂 Project structure

```plaintext
sha256-keccak256-research/
│── README.md # This file
│── LICENSE # Open source license
│── requirements.txt # Required Python packages
│── src/ # Main code
│ ├── setup.py # Build script for Cython extension
│ ├── sha256_buffer.c # Low-level C implementation for hashing & data management
│ ├── sha256_buffer.h # Header file for C
│ ├── sha256_extension.c # Generated C code from Cython
│ ├── sha256_extension.pyx # Cython bridge between Python & C
│ ├── training.py # TensorFlow AI model
```

---

## 📂 Data source & reproducibility

The quantum data used for this project was generated using **LFDR**'s **Quantum Random Number Generator API**:
🔗 [LFDR QRNG API documentation](https://www.lfdr.de/QRNG/)

pre-trained model for validation: https://drive.google.com/file/d/1he5Y4bl-dpSwMWh7aFHehkMzhwzGUqpa/view?pli=1

If further details are needed, the following can be provided upon request:
**Original data generation scripts**
**The full quantum data** (e.g quantum_data_async_len.bin & quantum_data_async_data.bin)

## 📥 Installation & Usage

### 🔧 Requirements
- Python 3.10
- TensorFlow 2.18.0
- NumPy, Cython, scikit-learn

---

### 📌 Installation

```bash
git clone https://github.com/demirkurekrobin/sha256-keccak256-research.git
cd sha256-keccak256-research
pip install -r requirements.txt
cd src/
python3.10 setup.py build_ext --inplace
python3.10 training.py
