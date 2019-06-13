pipeline {
    agent any

    environment {
        PROJECT = 'homestore'
        CONAN_CHANNEL = 'testing'
        CONAN_USER = 'sds'
        CONAN_PASS = credentials('CONAN_PASS')
    }

    stages {
        stage('Get Version') {
            steps {
                script {
                    TAG = sh(script: "grep 'version =' conanfile.py | awk '{print \$3}' | tr -d '\n' | tr -d '\"'", returnStdout: true)
                }
            }
        }

        stage('Build') {
            steps {
                sh "docker build --rm --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} -t ${PROJECT}-${TAG} ."
                sh "docker build -f Dockerfile.disco --rm --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} -t ${PROJECT}-${TAG}-disco ."
            }
        }

        stage('Test') {
            steps {
                sh "docker rm -f ${PROJECT}_coverage || true"
                sh "docker create --name ${PROJECT}_coverage ${PROJECT}-${TAG}"
                sh "docker cp ${PROJECT}_coverage:/output/coverage.xml coverage.xml"
                cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'coverage.xml', conditionalCoverageTargets: '20, 0, 0', fileCoverageTargets: '65, 0, 0', lineCoverageTargets: '45, 0, 0', maxNumberOfBuilds: 0, sourceEncoding: 'ASCII', zoomCoverageChart: false
            }
        }

        stage('Deploy') {
            when {
                branch "${CONAN_CHANNEL}/*"
            }
            steps {
                sh "docker run --rm ${PROJECT}-${TAG}"
                sh "docker run --rm ${PROJECT}-${TAG}-disco"
                slackSend channel: '#conan-pkgs', message: "*${PROJECT}/${TAG}@${CONAN_USER}/${CONAN_CHANNEL}* has been uploaded to conan repo."
            }
        }
    }

    post {
        always {
            sh "docker rm -f ${PROJECT}_coverage || true"
            sh "docker rmi -f ${PROJECT}-${TAG}"
            sh "docker rmi -f ${PROJECT}-${TAG}-disco"
        }
    }
}
