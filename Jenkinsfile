pipeline {
    agent any

    environment {
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
                sh "docker create --name ${PROJECT}_deploy ${PROJECT}"
                sh "docker cp ${PROJECT}_deploy:/output/coverage.xml coverage.xml"
                cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'coverage.xml', conditionalCoverageTargets: '20, 0, 0', fileCoverageTargets: '65, 0, 0', lineCoverageTargets: '45, 0, 0', maxNumberOfBuilds: 0, sourceEncoding: 'ASCII', zoomCoverageChart: false
            }
        }

        stage('Deploy') {
            when {
                branch "${CONAN_CHANNEL}/*"
            }
            steps {
                sh "docker start ${PROJECT}_deploy"
            }
        }
    }

    post {
        always {
            sh "docker rm -f ${PROJECT}_deploy"
            sh "docker rmi -f ${PROJECT}"
        }
    }
}
