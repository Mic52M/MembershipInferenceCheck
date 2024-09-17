import json
import sys
import os
import io
from mooncloud_driver import abstract_probe, atom, result, entrypoint
from git_ci import gitCI
import gitlab
import github
from github import GithubException
import onnxruntime as rt
import onnx
import numpy as np
import typing

class ONNXModelVulnerabilityProbe(abstract_probe.AbstractProbe):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.git_ci = None
        self.local_model_path = None

    def requires_credential(self) -> any:
        return True

    def parse_input(self):
        config = self.config.input.get("config", {})
        self.host = config.get('target')
        self.repo_type = config.get('repo_type', '').lower()
        self.project = config.get('project')
        self.branch = config.get('branch', 'master')
        self.artifact_path = config.get('artifact_path')
        self.job_name = config.get('job_name') if self.repo_type == "gitlab" else None
        self.artifact_name = config.get('artifact_name') if self.repo_type == "github" else None

        if not self.host or not self.repo_type or not self.project or not self.artifact_path:
            raise ValueError("Missing required input fields")

    def setup_git_ci(self):
        if self.repo_type == "gitlab":
            self.git_ci = gitCI(ci_type=gitCI.CIType.GITLAB, gl_domain=self.host, gl_token=self.config.credential.get('token'), gl_project=self.project)
        elif self.repo_type == "github":
            self.git_ci = gitCI(ci_type=gitCI.CIType.GITHUB, gh_domain=self.host, gh_token=self.config.credential.get('token'), gh_repo=self.project)
        else:
            raise ValueError("Unsupported repository type")

    def download_model(self):
        self.setup_git_ci()
        artifact_file = self.git_ci.getArtifact(branch_name=self.branch, job_name=self.job_name, artifact_path=self.artifact_path, artifact_name=self.artifact_name)

        if isinstance(artifact_file, io.TextIOWrapper):
            artifact_content = artifact_file.buffer.read()  
            artifact_file_path = f"/tmp/{os.path.basename(self.artifact_path)}"
            with open(artifact_file_path, 'wb') as f:
                f.write(artifact_content)
        elif isinstance(artifact_file, str):
            artifact_file_path = artifact_file
        else:
            raise ValueError("Unexpected artifact file type")

        if not os.path.exists(artifact_file_path):
            raise ValueError("Failed to download or find artifact")
        
        self.local_model_path = artifact_file_path

    def convert_onnx_model(self, model_path):
        model = onnx.load(model_path)
        model.ir_version = 3  
        converted_model_path = f"/tmp/converted_{os.path.basename(model_path)}"
        onnx.save(model, converted_model_path)
        return converted_model_path

    def load_onnx_model(self, model_path):
        session = rt.InferenceSession(model_path)
        input_name = session.get_inputs()[0].name
        output_name = session.get_outputs()[0].name
        input_shape = session.get_inputs()[0].shape
        return session, input_name, output_name, input_shape

    def analyze_model_output(self, model, input_name, output_name, input_shape):
        random_input = np.random.uniform(low=0, high=1, size=(1, *input_shape[1:]))
        adapted_input = self.adapt_input_shape(random_input, input_shape)
        output = self.predict_with_onnx(model, input_name, output_name, adapted_input)
        
        if len(output.shape) > 1 and output.shape[1] > 1:
            return True
        else:
            return False

    def predict_with_onnx(self, model, input_name, output_name, data):
        inputs = {input_name: data.astype(np.float32)}
        preds = model.run([output_name], inputs)
        return preds[0]

    def adapt_input_shape(self, data, input_shape):
        if len(data.shape) != len(input_shape):
            data = data.reshape((-1, *input_shape[1:]))
        return data

    def run_analysis(self, inputs: any) -> bool:
        self.download_model()
        try:
            session, input_name, output_name, input_shape = self.load_onnx_model(self.local_model_path)
        except rt.capi.onnxruntime_pybind11_state.RuntimeException as e:
            if 'Unsupported model IR version' in str(e):
                self.local_model_path = self.convert_onnx_model(self.local_model_path)
                session, input_name, output_name, input_shape = self.load_onnx_model(self.local_model_path)
            else:
                raise e

        is_vulnerable = self.analyze_model_output(session, input_name, output_name, input_shape)
        
        if is_vulnerable:
            self.result.integer_result = result.INTEGER_RESULT_TRUE
            self.result.pretty_result = "The model is potentially vulnerable to membership inference attacks."
        else:
            self.result.integer_result = result.INTEGER_RESULT_FALSE
            self.result.pretty_result = "The model is less vulnerable to membership inference attacks."
        
        return True

    def atoms(self) -> typing.Sequence[atom.AtomPairWithException]:
        return [
            atom.AtomPairWithException(
                forward=self.parse_input,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=ValueError,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_parse_exception
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.download_model,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=ValueError,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_artifact_exception
                    ),
                    atom.PunctualExceptionInformationForward(
                        exception_class=gitlab.GitlabAuthenticationError,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_gitlab_auth_error
                    ),
                    atom.PunctualExceptionInformationForward(
                        exception_class=gitlab.GitlabGetError,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_gitlab_get_error
                    ),
                    atom.PunctualExceptionInformationForward(
                        exception_class=github.GithubException,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_github_error
                    )
                ]
            ),
            atom.AtomPairWithException(
                forward=self.run_analysis,
                forward_captured_exceptions=[
                    atom.PunctualExceptionInformationForward(
                        exception_class=rt.capi.onnxruntime_pybind11_state.RuntimeException,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_onnx_runtime_error
                    ),
                    atom.PunctualExceptionInformationForward(
                        exception_class=ValueError,
                        action=atom.OnExceptionActionForward.STOP,
                        result_producer=self.handle_analysis_exception
                    )
                ]
            ),
        ]

    def handle_parse_exception(self, exception):
        pretty_result = "Parse Error: Unable to parse input."
        error_details = str(exception)
        return result.Result(
            integer_result=result.INTEGER_RESULT_INPUT_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": error_details}
        )

    def handle_gitlab_auth_error(self, exception):
        pretty_result = "GitLab Authentication Error: Unable to authenticate with GitLab."
        error_details = str(exception)
        return result.Result(
            integer_result=result.INTEGER_RESULT_TARGET_CONNECTION_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": error_details}
        )

    def handle_gitlab_get_error(self, exception):
        pretty_result = "GitLab Get Error: Unable to retrieve data from GitLab."
        error_details = str(exception)
        return result.Result(
            integer_result=result.INTEGER_RESULT_TARGET_CONNECTION_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": error_details}
        )

    def handle_github_error(self, exception):
        pretty_result = "GitHub Error: Unable to process GitHub request."
        error_details = str(exception)
        return result.Result(
            integer_result=result.INTEGER_RESULT_TARGET_CONNECTION_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": error_details}
        )

    def handle_artifact_exception(self, exception):
        pretty_result = f"Artifact Error: {str(exception)}"
        return result.Result(
            integer_result=result.INTEGER_RESULT_INPUT_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": "Artifact not found"}
        )

    def handle_onnx_runtime_error(self, exception):
        pretty_result = f"ONNX Runtime Error: {str(exception)}"
        if 'Unsupported model IR version' in str(exception):
            pretty_result = "ONNX Runtime Error: Unsupported model IR version. Trying to convert model."
            self.local_model_path = self.convert_onnx_model(self.local_model_path)
            return result.Result(
                integer_result=result.INTEGER_RESULT_TARGET_CONNECTION_ERROR,
                pretty_result=pretty_result,
                base_extra_data={"Error": str(exception)}
            )
        return result.Result(
            integer_result=result.INTEGER_RESULT_TARGET_EXECUTION_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": str(exception)}
        )

    def handle_analysis_exception(self, exception):
        pretty_result = "Analysis Error: Unable to analyze the model."
        error_details = str(exception)
        return result.Result(
            integer_result=result.INTEGER_RESULT_TARGET_EXECUTION_ERROR,
            pretty_result=pretty_result,
            base_extra_data={"Error": error_details}
        )

if __name__ == '__main__':
    entrypoint.start_execution(ONNXModelVulnerabilityProbe)

