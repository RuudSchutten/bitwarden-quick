namespace BwQuick.Core.Items;

public static class VaultSearch
{
    public static List<VaultEntry> Search(
        IReadOnlyList<VaultEntry> entries,
        string query,
        IReadOnlyList<string> recentIds,
        int limit = 50)
    {
        var tokens = query.ToLowerInvariant().Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var recentRank = new Dictionary<string, int>(recentIds.Count);
        for (var i = 0; i < recentIds.Count; i++) recentRank.TryAdd(recentIds[i], i);

        if (tokens.Length == 0)
        {
            var recent = recentIds
                .Select(id => entries.FirstOrDefault(e => e.Id == id))
                .OfType<VaultEntry>();
            var favorites = entries.Where(e => e.Favorite && !recentRank.ContainsKey(e.Id));
            var rest = entries.Where(e => !e.Favorite && !recentRank.ContainsKey(e.Id));
            return recent.Concat(favorites).Concat(rest).Take(limit).ToList();
        }

        var scored = new List<(VaultEntry Entry, int Score)>();
        foreach (var entry in entries)
        {
            var total = 0;
            foreach (var token in tokens)
            {
                var score = ScoreToken(entry, token);
                if (score == 0) { total = 0; break; }
                total += score;
            }
            if (total == 0) continue;

            if (entry.Favorite) total += 5;
            if (recentRank.TryGetValue(entry.Id, out var rank)) total += Math.Max(0, 20 - rank);
            scored.Add((entry, total));
        }

        scored.Sort((a, b) =>
        {
            var byScore = b.Score.CompareTo(a.Score);
            return byScore != 0 ? byScore : string.Compare(a.Entry.Name, b.Entry.Name, StringComparison.CurrentCultureIgnoreCase);
        });

        var result = new List<VaultEntry>(Math.Min(limit, scored.Count));
        for (var i = 0; i < scored.Count && i < limit; i++) result.Add(scored[i].Entry);
        return result;
    }

    private static int ScoreToken(VaultEntry e, string token)
    {
        if (e.NameLower.StartsWith(token, StringComparison.Ordinal)) return 100;
        if (e.HostLower.StartsWith(token, StringComparison.Ordinal)) return 70;
        if (IsWordStart(e.NameLower, token)) return 60;
        if (e.NameLower.Contains(token, StringComparison.Ordinal)) return 40;
        if (e.HostLower.Contains(token, StringComparison.Ordinal)) return 30;
        if (e.UsernameLower.Contains(token, StringComparison.Ordinal)) return 20;
        if (e.UriLower.Contains(token, StringComparison.Ordinal)) return 10;
        return 0;
    }

    private static bool IsWordStart(string haystack, string token)
    {
        var index = haystack.IndexOf(token, StringComparison.Ordinal);
        while (index > 0)
        {
            if (!char.IsLetterOrDigit(haystack[index - 1])) return true;
            index = haystack.IndexOf(token, index + 1, StringComparison.Ordinal);
        }
        return false;
    }
}
