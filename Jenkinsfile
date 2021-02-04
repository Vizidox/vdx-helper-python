nexus_url = 'https://nexus.morphotech.co.uk/repository/pypi-hosted/'
sonar_url = 'https://sonar.morphotech.co.uk'
sonar_project_key = 'vdx-helper'
sonar_analyzed_dir = 'vdx_helper'
docker_image_tag = "vdx-helper"

pipeline {
    agent {
        label env.agent_label
    }
    stages {
        stage('Build docker') {
            steps {
             sh "docker-compose build"
            }
        }
        stage('Run Tests') {
            steps{
                script{
                    if(!params.get('skipTests', false)) {
                        sh "docker-compose up -d"
                        sh "sleep 3" // prism seems not to be fully up, so some seconds of sleep are needed
                        sh "docker-compose run vdx-helper pytest tests --junitxml=/coverage/pytest-report.xml --cov-report=xml:/coverage/coverage.xml --cov=${sonar_analyzed_dir}"
                    }
                }
            }
        }
        stage('Push to Nexus') {
            steps {
                sh "docker-compose run ${docker_image_tag} /bin/bash -c \"poetry config repositories.morphotech ${nexus_url}; poetry config http-basic.morphotech ${env.nexus_account} ${env.nexus_password}; poetry build; poetry publish -r morphotech\""
            }
        }
//         stage('Sonarqube code inspection') {
//             steps {
//                 sh "docker run --rm -e SONAR_HOST_URL=\"${sonar_url}\" -v \"${WORKSPACE}:/usr/src\"  sonarsource/sonar-scanner-cli:4.4 -X \
//                 -Dsonar.projectKey=${sonar_project_key}\
//                 -Dsonar.login=${env.sonar_account}\
//                 -Dsonar.password=${env.sonar_password}\
//                 -Dsonar.python.coverage.reportPaths=coverage/coverage.xml\
//                 -Dsonar.python.xunit.reportPath=coverage/pytest-report.xml\
//                 -Dsonar.projectBaseDir=${sonar_analyzed_dir}"
//             }
//         }
    }
    post {
        cleanup{
            sh "docker-compose down"
        }
    }
}
