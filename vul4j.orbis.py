from pathlib import Path
from typing import List, Dict, Any, AnyStr

from cement import Handler

from orbis.data.misc import Context
from orbis.data.results import CommandData
from orbis.data.schema import Oracle, Project
from orbis.ext.database import TestOutcome
from orbis.handlers.benchmark.java_benchmark import JavaBenchmark


class VUL4J(JavaBenchmark):
    """
        Handler for interacting locally with the Vul4J benchmark
    """

    class Meta:
        label = 'vul4j'

    def set(self, project: Project):
        """Sets the env variables for the operations."""
        self.env["MAVEN_HOME"] = project.packages.get('maven_home')
        self.env["PATH"] += ":" + self.env["MAVEN_HOME"] + "/bin"

        if project.build.version == '7':
            self.env["JAVA_HOME"] = project.packages.get('java7_home')
        else:
            self.env["JAVA_HOME"] = project.packages.get('java8_home')

    def classpath(self, context: Context) -> AnyStr:
        maven_local_repo = str(context.root.resolve()) + "/.m2/repository"
        self.env["MVN_OPTS"] = "-Dmaven.repo.local=" + maven_local_repo  # MVN_OPTS env works for only vul4j

        manifest = context.project.get_version(sha=context.instance.sha)
        checkout_dir = context.root.resolve() / context.project.name
        cmd_data = CommandData(args=f"vul4j classpath -d {checkout_dir}", cwd=str(context.root.resolve() / context.project.name), env=self.env)
        super().__call__(cmd_data=cmd_data, msg=f"Getting classpath of {manifest.vuln.id}\n", raise_err=True)
        res = cmd_data.output[2:][:-2]
        return res

    def checkout(self, vid: str, working_dir: str = None, root_dir: str = None, **kwargs) -> Dict[str, Any]:

        project = self.get_by_vid(vid)
        manifest = project.get_manifest(vid)
        corpus_path = Path(self.get_config('corpus'))  # benchmark repository path

        iid, working_dir = self.checkout_handler(project, manifest=manifest, corpus_path=corpus_path,
                                                 working_dir=working_dir, root_dir=root_dir)

        # save extra json file containing information about the vulnerability (for only vul4j)
        checkout_dir = working_dir.resolve() / project.name
        info_folder = checkout_dir / "VUL4J"
        cmd_data = CommandData(args=f"mkdir {info_folder}; vul4j info -i {manifest.vuln.id} > {info_folder}/vulnerability_info.json", cwd="/", env=self.env)
        super().__call__(cmd_data=cmd_data, msg=f"Saving information of {manifest.vuln.id}\n", raise_err=True)

        return {'iid': iid, 'working_dir': str(working_dir.resolve())}

    def build(self, context: Context, **kwargs) -> CommandData:
        build_handler = self.app.handler.get('handlers', 'java_build', setup=True)
        manifest = context.project.get_version(sha=context.instance.sha)

        if manifest.vuln.build.system == "Maven":
            cmd_data = build_handler.build_maven(context, self.env)
            cmd_data['build'] = str(context.root.resolve() / context.project.name / 'target')
        elif manifest.vuln.build.system == "Gradle":
            cmd_data = build_handler.build_gradle(context, self.env)
            cmd_data['build'] = str(context.root.resolve() / context.project.name / 'build')
        else:
            cmd_data = CommandData(args="")
        return cmd_data

    def test(self, context: Context, tests: Oracle, timeout: int, **kwargs) -> List[TestOutcome]:
        test_handler = self.app.handler.get('handlers', 'java_test', setup=True)
        manifest = context.project.get_version(sha=context.instance.sha)

        test_outcomes = []

        for name, test in tests.cases.items():
            if manifest.vuln.build.system == "Maven":
                cmd_data, outcome = test_handler.test_maven(context, test, self.env)
                test_outcomes.append(outcome)
            elif manifest.vuln.build.system == "Gradle":
                cmd_data, outcome = test_handler.test_gradle(context, test, self.env)
                test_outcomes.append(outcome)

        return test_outcomes

    def make(self, context: Context, handler: Handler, **kwargs) -> CommandData:
        pass

    def gen_tests(self, project: Project, **kwargs) -> CommandData:
        pass

    def gen_povs(self, project: Project, **kwargs) -> CommandData:
        pass


def load(nexus):
    nexus.handler.register(VUL4J)
