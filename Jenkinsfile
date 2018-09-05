pipeline {
    agent any

    environment {
        PROJECT = 'homestore'
        CONAN_CHANNEL = 'stable'
        CONAN_USER = 'sds'
        CONAN_PASS = credentials('CONAN_PASS')
    }

    stages {
        stage('Build') {
            steps {
                sh "docker build --rm --build-arg CONAN_USER=${CONAN_USER} --build-arg CONAN_PASS=${CONAN_PASS} --build-arg CONAN_CHANNEL=${CONAN_CHANNEL} -t ${PROJECT} ."
            }
        }

        stage('Test') {
            steps {
                sh "docker create --name ${PROJECT}_coverage ${PROJECT}"
                sh "docker cp ${PROJECT}_coverage:/output/coverage.xml coverage.xml"
                sh "docker rm -f ${PROJECT}_coverage"
                cobertura autoUpdateHealth: false, autoUpdateStability: false, coberturaReportFile: 'coverage.xml', conditionalCoverageTargets: '20, 0, 0', fileCoverageTargets: '65, 0, 0', lineCoverageTargets: '45, 0, 0', maxNumberOfBuilds: 0, sourceEncoding: 'ASCII', zoomCoverageChart: false
            }
        }

        stage('Deploy') {
            when {
                branch "${CONAN_CHANNEL}/*"
            }
            steps {
                sh "docker run --rm ${PROJECT}"
            }
        }
    }

    post {
        always {
            sh "docker rmi -f ${PROJECT}"
        }
    }
}
