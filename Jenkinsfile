pipeline {
    agent any

    tools {
        nodejs 'node22' // must match your NodeJS plugin config name
    }

    triggers {
        // If using Gitea plugin:
        // gitlabPush(branchFilterType: 'All')
        // Otherwise generic SCM polling as fallback:
        pollSCM('* * * * *')
    }

    environment {
        DEPLOY_HOST = 'web-dev'
        DEPLOY_USER = 'deploy'
        DEPLOY_PATH = '/var/www/red-team'
        SSH_CRED_ID = 'james' // Jenkins credential ID
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install') {
            steps {
                sh 'npm ci'
            }
        }

        stage('Build') {
            steps {
                sh 'npm run build'
                // Astro outputs to ./dist by default
            }
        }

        stage('Deploy') {
            steps {
                sshagent(credentials: [env.SSH_CRED_ID]) {
                    sh """
                    rsync -avz --delete \
                        --chmod=D755,F644 \
                        -e 'ssh -o StrictHostKeyChecking=no' \
                        dist/ \
                        ${env.DEPLOY_USER}@${env.DEPLOY_HOST}:${env.DEPLOY_PATH}/

                    ssh -o StrictHostKeyChecking=no \
                        ${env.DEPLOY_USER}@${env.DEPLOY_HOST} \
                        'sudo systemctl reload apache2'
                """
                }
            }
        }

    post {
        success {
            echo 'Astro site deployed successfully.'
        }
        failure {
            echo 'Build or deploy failed.'
        }
    }
}