class GqlQueries:
    """Constructs GraphQL queries for use with the GitHub GraphQL API.\n    """

    GET_YMLS_WITH_SLUGS = """\n    fragment repoWorkflows on Repository {\n        nameWithOwner\n        stargazers {\n            totalCount\n        }\n        isPrivate\n        isArchived\n        viewerPermission\n        url\n        isFork\n        pushedAt\n        defaultBranchRef {\n            name\n        }\n        object(expression: "HEAD:.github/workflows/") {\n            ... on Tree {\n                entries {\n                    name\n                    type\n                    mode\n                    object {\n                        ... on Blob {\n                            byteSize\n                            text\n                        }\n                    }\n                }\n            }\n        }\n    }\n    """

    GET_YMLS = """\n    query RepoFiles($node_ids: [ID!]!) {\n        nodes(ids: $node_ids) {\n            ... on Repository {\n                nameWithOwner\n                isPrivate\n                isArchived\n                stargazers {\n                    totalCount\n                }\n                viewerPermission\n                pushedAt\n                url\n                isFork\n                defaultBranchRef {\n                    name\n                }\n                object(expression: "HEAD:.github/workflows/") {\n                    ... on Tree {\n                        entries {\n                            name\n                            type\n                            mode\n                            object {\n                                ... on Blob {\n                                    byteSize\n                                    text\n                                }\n                            }\n                        }\n                    }\n                }\n            }\n        }\n    }\n    """

    GET_YMLS_ENV = """\n    query RepoFiles($node_ids: [ID!]!) {\n        nodes(ids: $node_ids) {\n            ... on Repository {\n                nameWithOwner\n                isPrivate\n                isArchived\n                stargazers {\n                    totalCount\n                }\n                viewerPermission\n                pushedAt\n                url\n                isFork\n                environments(first: 100) {\n                    edges {\n                        node {\n                            id\n                            name\n                        }\n                    }\n                }\n                defaultBranchRef {\n                    name\n                }\n                object(expression: "HEAD:.github/workflows/") {\n                    ... on Tree {\n                        entries {\n                            name\n                            type\n                            mode\n                            object {\n                                ... on Blob {\n                                    byteSize\n                                    text\n                                }\n                            }\n                        }\n                    }\n                }\n            }\n        }\n    }\n    """

    @staticmethod
    def get_workflow_ymls_from_list(repos: list):
        """\n        Constructs a list of GraphQL queries to fetch workflow YAML \n        files from a list of repositories.\n\n        This method splits the list of repositories into chunks of \n        up to 50 repositories each, and constructs a separate\n        GraphQL query for each chunk. Each query fetches the workflow \n        YAML files from the repositories in one chunk.\n\n        Args:\n            repos (list): A list of repository slugs, where each \n            slug is a string in the format "owner/name".\n\n        Returns:\n            list: A list of dictionaries, where each dictionary \n            contains a single GraphQL query in the format:\n            {"query": "<GraphQL query string>"}.\n        """
        
        queries = []

        for i in range(0, len(repos), 50):
            chunk = repos[i:i + 50]
            repo_queries = []

            for j, repo in enumerate(chunk):
                owner, name = repo.split('/')
                repo_query = f"""\n                repo{j + 1}: repository(owner: "{owner}", name: "{name}") {{\n                    ...repoWorkflows\n                }}\n                """
                repo_queries.append(repo_query)

            queries.append(
                {"query": GqlQueries.GET_YMLS_WITH_SLUGS + "{\n" + "\n".join(repo_queries) + "\n}"}
            )

        return queries

    @staticmethod
    def get_workflow_ymls(repos: list):
        """Retrieve workflow YAML files for each repository.\n\n        Args:\n            repos (List[Repository]): List of repository objects\n        Returns:\n            (list): List of JSON post parameters for each GraphQL query.\n        """
        queries = []

        if len(repos) == 0:
            return queries

        # Enhance repository management by checking permissions centrally
        can_push_any = any(repo.can_push() for repo in repos)

        for i in range(0, (len(repos) // 100) + 1):
            top_len = len(repos) if len(repos) < (100 + i*100) else (100 + i*100)
            node_ids = [repo.repo_data['node_id'] for repo in repos[i*100:top_len]]

            query = {
                "query": GqlQueries.GET_YMLS_ENV if can_push_any else GqlQueries.GET_YMLS,
                "variables": {
                    "node_ids": node_ids
                }
            }

            queries.append(query)
        return queries