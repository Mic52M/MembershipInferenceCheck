# MembershipInferenceCheck
This probe evaluates ONNX models to determine their vulnerability to membership inference attacks, a type of privacy threat. It analyzes the model's behavior probabilistically to assess the risk of sensitive data exposure based on its predictions.


## Overview

The `ONNXModelVulnerabilityProbe` is designed to assess the vulnerability of ONNX-based machine learning models to **membership inference attacks**. These attacks aim to infer whether specific data points were used in the training set, posing a privacy risk. By examining the probabilistic nature of the model’s outputs, this probe helps identify models that may be susceptible to these attacks, making it a crucial tool for securing machine learning models in production.

## Core Functionality

### 1. **Input Parsing and CI Integration**
The probe begins by retrieving the necessary inputs, such as the target server and repository information, from a CI/CD pipeline. It supports both GitLab and GitHub repositories for pulling the model artifacts. Key configuration details include:
- **Host**: The CI server (e.g., GitLab or GitHub) where the model artifact is stored.
- **Repository Type**: GitLab or GitHub.
- **Project, Branch, and Artifact Details**: Defines the location and version of the model to be analyzed.

Once the inputs are parsed, the probe connects to the GitLab or GitHub repository using the `gitCI` interface and downloads the ONNX model from the specified location.

### 2. **Model Download and Conversion**
The probe downloads the ONNX model artifact from the repository. If the downloaded ONNX model uses an unsupported Intermediate Representation (IR) version, the probe automatically converts the model to a supported IR version (3). This ensures compatibility with ONNX runtime for further analysis.

### 3. **Model Loading and Inference**
The probe loads the ONNX model using `onnxruntime`, a runtime environment for executing ONNX models. During this process, the probe:
- Retrieves the model’s input and output names, as well as the input shape.
- Generates random input data with the same shape as the model's expected input.
  
### 4. **Vulnerability Analysis**
The core of the vulnerability analysis focuses on evaluating whether the model’s output has characteristics that make it prone to **membership inference attacks**. The probe checks the nature of the model’s predictions, specifically looking for signs that the model produces outputs that vary significantly based on whether a data point was in the training set.

The probe runs a forward pass with random input data, analyzing the output’s dimensionality and distribution:
- If the output is multidimensional (with more than one class or output feature), it suggests a higher likelihood of the model being vulnerable to membership inference attacks. This is based on how models with probabilistic outputs can expose information about whether certain data points were in the training set.

### 5. **Result Reporting**
Depending on the analysis, the probe provides a clear assessment of the model's vulnerability:
- **Vulnerable Models**: If the model is deemed vulnerable, the result will be marked as `INTEGER_RESULT_TRUE`, with a message stating that the model is potentially vulnerable to membership inference attacks.
- **Non-vulnerable Models**: If the model is less vulnerable, the result will be marked as `INTEGER_RESULT_FALSE`, indicating a lower likelihood of privacy leakage.

These results are reported in a human-readable format and can be integrated into CI/CD pipelines for automated security assessments of machine learning models.

## Key Methods

- **`download_model()`**: Downloads the ONNX model artifact from GitLab or GitHub.
- **`convert_onnx_model()`**: Converts the ONNX model to a compatible IR version if necessary.
- **`load_onnx_model()`**: Loads the ONNX model and retrieves key information such as input/output names and shapes.
- **`analyze_model_output()`**: Performs the core vulnerability analysis by evaluating the model’s probabilistic output and assessing the risk of membership inference attacks.
- **`adapt_input_shape()`**: Ensures that the generated input data matches the expected input shape of the ONNX model.
- **`predict_with_onnx()`**: Runs the ONNX model on the input data and retrieves the output for analysis.

## Error Handling

The probe includes detailed error handling to cover a range of issues:
- **SSH and Authentication Errors**: Handles errors related to connecting to GitLab or GitHub repositories, including authentication failures.
- **Model Download Issues**: If the model artifact is missing or cannot be downloaded, the probe provides a clear error message.
- **ONNX Model Compatibility**: If the model uses an unsupported IR version, the probe attempts to convert it. If the conversion fails, an appropriate error is raised.
- **Model Analysis Failures**: If the model cannot be analyzed (due to unsupported operations or malformed outputs), the probe raises a descriptive error message.

## Use Case in MLOps

This probe is designed to be used in MLOps pipelines where automated model security assessments are necessary before deployment. It ensures that ONNX models are evaluated for their vulnerability to membership inference attacks, protecting against potential privacy breaches in production environments.
