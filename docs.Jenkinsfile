pipeline {
    agent {
        label env.agent_label
    }
    stages {
        stage('Build Docs') {
            steps {
                sh "docker build -f ${env.workspace}/docs.Dockerfile -t nexus.morphotech.co.uk/vdx-helper-docs ."
            }
        }
        stage('Push to PyPi') {
            steps {
                sh "docker push nexus.morphotech.co.uk/vdx-helper-docs:latest"
            }
        }
    }
    post {
        cleanup{
            sh "docker-compose down"
        }
    }
}
