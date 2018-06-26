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
        stage('Get Version') {
            steps {
                script {
                    TAG = sh(script: "grep version conanfile.py | awk '{print \$3}' | tr -d '\n' | tr -d '\"'", returnStdout: true)
                }
            }
        }

        stage('Build') {
            steps {
                sh "docker build --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} -t ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${TAG} ."
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
                sh "docker run ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${TAG}"
            }
        }
    }
}
