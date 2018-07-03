pipeline {
    agent any

    environment {
        ORG = 'sds'
        PROJECT = 'homestore'
        CONAN_CHANNEL = 'testing'
        CONAN_USER = 'sds'
        CONAN_PASS = credentials('CONAN_PASS')
    }

    stages {
        stage('Build') {
            steps {
                sh "docker build --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} -t ${PROJECT} ."
            }
        }

        stage('Test') {
            steps {
                echo "Tests go here"
            }
        }

        stage('Deploy') {
            when {
                branch 'master'
            }
            steps {
                sh "docker run ${PROJECT}"
            }
        }
    }

    post {
        always {
            sh "docker rmi ${PROJECT}"
        }
    }
}
