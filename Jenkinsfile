pipeline {
    agent any

    environment {
        ORG = 'sds'
        CONAN_USER = 'sds'
        CONAN_PASS = credentials('CONAN_PASS')
        MASTER_BRANCH = 'develop'
        STABLE_BRANCH = 'testing/*'
    }

    stages {
        stage('Get Version') {
            steps {
                script {
                    PROJECT = sh(script: "grep -m 1 'name =' conanfile.py | awk '{print \$3}' | tr -d '\n' | tr -d '\"'", returnStdout: true)
                    CONAN_CHANNEL = sh(script: "echo ${BRANCH_NAME} | sed -E 's,(\\w+).*,\\1,' | tr -d '\n'", returnStdout: true)
                    TAG = sh(script: "grep -m 1 'version =' conanfile.py | awk '{print \$3}' | tr -d '\n' | tr -d '\"'", returnStdout: true)
                }
            }
        }

        stage('Coverage') {
            when {
                branch "disabled"
            }
            steps {
                sh "docker build -f Dockerfile.sonar --rm --build-arg COVERAGE_ON='true' --build-arg BUILD_TYPE=debug --build-arg BRANCH_NAME=${BRANCH_NAME} --build-arg HOMESTORE_BUILD_TAG=${GIT_COMMIT} ."
            }
        }

        stage('Build') {
            steps {
                sh "docker build --rm --build-arg BUILD_TYPE=debug --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} --build-arg HOMESTORE_BUILD_TAG=${GIT_COMMIT} -t ${PROJECT}-${GIT_COMMIT}-debug ."
                sh "docker build --rm --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} --build-arg HOMESTORE_BUILD_TAG=${GIT_COMMIT} -t ${PROJECT}-${GIT_COMMIT}-release ."
            }
        }

        stage('Deploy') {
            steps {
                sh "docker run --rm ${PROJECT}-${GIT_COMMIT}-debug"
                sh "docker run --rm ${PROJECT}-${GIT_COMMIT}-release"
                slackSend channel: '#conan-pkgs', message: "*${PROJECT}/${TAG}@${CONAN_USER}/${CONAN_CHANNEL}* has been uploaded to conan repo."
            }
        }

        stage('TestImage') {
            when {
                branch "develop"
                branch "snapshot"
            }
            steps {
                withDockerRegistry([credentialsId: 'sds+sds', url: "https://ecr.vip.ebayc3.com"]) {
                    sh "docker build -f Dockerfile.test --rm --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} --build-arg HOMESTORE_BUILD_TAG=${GIT_COMMIT} -t ${PROJECT}-${GIT_COMMIT}-test ."
                    sh "docker tag ${PROJECT}-${GIT_COMMIT}-test ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${CONAN_CHANNEL}-test"
                    sh "docker push ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${CONAN_CHANNEL}-test"
                    sh "docker rmi ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${CONAN_CHANNEL}-test"
                    slackSend channel: '#conan-pkgs', message: "*${PROJECT}:${CONAN_CHANNEL}-test* has been pushed to ECR."

                    sh "docker build -f Dockerfile.test --rm --build-arg BUILD_TYPE=release --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} --build-arg HOMESTORE_BUILD_TAG=${GIT_COMMIT} -t ${PROJECT}-${GIT_COMMIT}-release ."
                    sh "docker tag ${PROJECT}-${GIT_COMMIT}-release ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${CONAN_CHANNEL}-release"
                    sh "docker push ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${CONAN_CHANNEL}-release"
                    sh "docker rmi ecr.vip.ebayc3.com/${ORG}/${PROJECT}:${CONAN_CHANNEL}-release"
                    slackSend channel: '#conan-pkgs', message: "*${PROJECT}:${CONAN_CHANNEL}-release* has been pushed to ECR."
                }
            }
        }
    }

    post {
        always {
            sh "docker rmi -f ${PROJECT}-${GIT_COMMIT}-debug"
            sh "docker rmi -f ${PROJECT}-${GIT_COMMIT}-release"
            sh "docker rmi -f ${PROJECT}-${GIT_COMMIT}-release"
            sh "docker rmi -f ${PROJECT}-${GIT_COMMIT}-test"
        }
    }
}
