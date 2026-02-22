import observation_service


def test_normalize_observation_filters_handles_invalid_inputs():
    result = observation_service.normalize_observation_filters_core(
        analyst='  Alice  ',
        confidence='INVALID',
        updated_from='2026-02-30',
        updated_to='2026-02-22',
    )
    assert result['analyst'] == 'alice'
    assert result['confidence'] == ''
    assert result['updated_from'] == ''
    assert result['updated_to'] == '2026-02-22'


def test_build_observation_where_clause_uses_normalized_filters():
    where_sql, params = observation_service.build_observation_where_clause_core(
        'actor-1',
        filters={
            'analyst': 'alice',
            'confidence': 'high',
            'updated_from': '2026-02-01',
            'updated_to': '2026-02-22',
        },
    )
    assert where_sql == (
        'actor_id = ? AND LOWER(updated_by) LIKE ? AND confidence = ? '
        'AND substr(updated_at, 1, 10) >= ? AND substr(updated_at, 1, 10) <= ?'
    )
    assert params == ['actor-1', '%alice%', 'high', '2026-02-01', '2026-02-22']


def test_observation_source_keys_and_row_mapping():
    rows = [
        ('source', 'src-1', 'note', 'ref', 'high', 'A', '1', 'alice', '2026-02-22T12:00:00+00:00'),
        ('other', 'x', 'note2', '', 'low', '', '', 'bob', '2026-02-20T12:00:00+00:00'),
    ]
    keys = observation_service.observation_source_keys_core(rows)
    assert keys == ['src-1']

    items = observation_service.map_observation_rows_core(
        rows,
        source_lookup={
            'src-1': {
                'source_name': 'CISA',
                'source_url': 'https://example.test',
                'source_title': 'Example title',
                'source_date': '2026-02-20',
            }
        },
    )
    assert items[0]['source_name'] == 'CISA'
    assert items[0]['item_key'] == 'src-1'
    assert items[1]['source_name'] == ''


def test_source_lookup_chunks_respects_chunk_size():
    keys = [f'k-{idx}' for idx in range(1805)]
    chunks = observation_service.source_lookup_chunks_core(keys, chunk_size=800)
    assert len(chunks) == 3
    assert len(chunks[0]) == 800
    assert len(chunks[1]) == 800
    assert len(chunks[2]) == 205
