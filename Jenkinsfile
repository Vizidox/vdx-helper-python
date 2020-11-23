nexus_url = 'https://nexus.morphotech.co.uk/repository/pypi-hosted/'
sonar_url = 'https://sonar.morphotech.co.uk'
sonar_project_key = 'vdx-helper'
sonar_analyzed_dir = 'vdx-helper'
docker_image_tag = "vdx-helper"

pipeline {
    agent {
        label env.agent_label
    }
    stages {
        stage('Build docker') {
            steps {
             sh "docker build . -t ${docker_image_tag}"
            }
        }

        stage('Run Tests') {
            steps{
                script{
                    if(!params.get('skipTests', false)) {
                        sh "docker run -v ${WORKSPACE}/coverage:/coverage ${docker_image_tag} pytest --junitxml=/coverage/pytest-report.xml --cov-report=xml:/coverage/coverage.xml --cov=${sonar_analyzed_dir}"
                    }
                }
            }
        }
        stage('Push to Nexus and remove the container') {
            steps {
                sh "docker run ${docker_image_tag} /bin/bash -c \"poetry config repositories.morphotech ${nexus_url}; poetry config http-basic.morphotech ${env.nexus_account} ${env.nexus_password}; poetry build; poetry publish -r morphotech\""
            }
        }
        stage('Sonarqube code inspection') {
            steps {
                sh "docker run --rm -e SONAR_HOST_URL=\"${sonar_url}\" -v \"${WORKSPACE}:/usr/src\"  sonarsource/sonar-scanner-cli:4.4 -X \
                -Dsonar.projectKey=${sonar_project_key}\
                -Dsonar.login=${env.sonar_account}\
                -Dsonar.password=${env.sonar_password}\
                -Dsonar.python.coverage.reportPaths=coverage/coverage.xml\
                -Dsonar.python.xunit.reportPath=coverage/pytest-report.xml\
                -Dsonar.projectBaseDir=${sonar_analyzed_dir}"
            }
        }
    }
}
