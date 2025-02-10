class GqlQueries:
    """Constructs GraphQL queries for use with the GitHub GraphQL API.
    """

    GET_YMLS_WITH_SLUGS = """
    fragment repoWorkflows on Repository {
        nameWithOwner
        url
        isPrivate
        isArchived
        isFork
        forkingAllowed
        stargazers {
            totalCount
        }
        viewerPermission
        pushedAt
        defaultBranchRef {
            name
        }
        object(expression: "HEAD:.github/workflows/") {
            ... on Tree {
                entries {
                    name
                    type
                    mode
                    object {
                        ... on Blob {
                            byteSize
                            text
                        }
                    }
                }
            }
        }
    }
    """

    GET_YMLS = """
    query RepoFiles($node_ids: [ID!]!) {
        nodes(ids: $node_ids) {
            ... on Repository {
                nameWithOwner
                url
                isPrivate
                isArchived
                isFork
                forkingAllowed
                stargazers {
                    totalCount
                }
                viewerPermission
                pushedAt
                defaultBranchRef {
                    name
                }
                object(expression: "HEAD:.github/workflows/") {
                    ... on Tree {
                        entries {
                            name
                            type
                            mode
                            object {
                                ... on Blob {
                                    byteSize
                                    text
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """

    GET_YMLS_ENV = """
    query RepoFiles($node_ids: [ID!]!) {
        nodes(ids: $node_ids) {
            ... on Repository {
                nameWithOwner
                url
                isPrivate
                isArchived
                isFork
                forkingAllowed
                stargazers {
                    totalCount
                }
                viewerPermission
                pushedAt
                environments(first: 100) {
                    edges {
                        node {
                            id
                            name
                        }
                    }
                }
                defaultBranchRef {
                    name
                }
                object(expression: "HEAD:.github/workflows/") {
                    ... on Tree {
                        entries {
                            name
                            type
                            mode
                            object {
                                ... on Blob {
                                    byteSize
                                    text
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """

    @staticmethod
    def get_workflow_ymls_from_list(repos: list):
        """
        Constructs a list of GraphQL queries to fetch workflow YAML 
        files from a list of repositories.

        This method splits the list of repositories into chunks of 
        up to 100 repositories each, and constructs a separate
        GraphQL query for each chunk. Each query fetches the workflow 
        YAML files from the repositories in one chunk.

        Args:
            repos (list): A list of repository slugs, where each 
            slug is a string in the format "owner/name".

        Returns:
            list: A list of dictionaries, where each dictionary 
            contains a single GraphQL query in the format:
            {"query": "<GraphQL query string>"}.
        """
        queries = []

        for i in range(0, len(repos), 100):
            chunk = repos[i:i + 100]
            repo_queries = []

            for j, repo in enumerate(chunk):
                owner, name = repo.split('/')
                repo_query = f"""
                repo{j + 1}: repository(owner: "{owner}", name: "{name}") {{
                    ...repoWorkflows
                }}
                """
                repo_queries.append(repo_query)

            queries.append(
                {"query": GqlQueries.GET_YMLS_WITH_SLUGS + "{\n" + "\n".join(repo_queries) + "\n}"}
            )

        return queries

    @staticmethod
    def get_workflow_ymls(repos: list):
        """Retrieve workflow YAML files for each repository.

        Args:
            repos (List[Repository]): List of repository objects

        Returns:
            list: List of JSON post parameters for each GraphQL query.
        """
        queries = []

        if len(repos) == 0:
            return queries

        for i in range(0, (len(repos) // 100) + 1):
            top_len = min(len(repos), 100 + i * 100)
            can_push = any(repo.can_push() for repo in repos[i * 100:top_len])
            query = {
                "query": GqlQueries.GET_YMLS_ENV if can_push else GqlQueries.GET_YMLS,
                "variables": {
                    "node_ids": [repo.repo_data['node_id'] for repo in repos[i * 100:top_len]]
                }
            }

            queries.append(query)

        return queries